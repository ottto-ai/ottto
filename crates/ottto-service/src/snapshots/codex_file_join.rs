//! Local proof for joining physical Codex rollouts. Requested-tier selectors
//! retain the existing reader's meaning; response ownership is a separate fact.
use super::*;
use crate::transcript_acquisition::FileStamp;

mod group_job;
pub(super) use group_job::{
    disclose_members, disclose_strict, end_group, group_counting_is_v2, job_key,
    refusal_disclosure, step_group, take_charge, Boot, EndInputs, GroupBoot, GroupEnd, GroupJob,
    GroupStep, JobInputs, StepInputs,
};

pub(super) const MAX_HEADER_BYTES: usize = 64 * 1024;

pub(super) const MAX_HEADER_FILES: usize = 32_768;
// Bound cumulative I/O by the supported population and individual secure
// read bounds. Native headers may contain sizeable instructions; an unrelated
// 32MiB ceiling permanently refused otherwise-valid inventories. Reads still
// yield one header per step, and no decoded header is retained between steps.
const MAX_HEADER_READ_BYTES: usize = MAX_HEADER_FILES * (MAX_HEADER_BYTES + 1);

fn metadata_witness(metadata: &fs::Metadata) -> String {
    let mut digest = Sha256::new();
    digest.update(metadata.len().to_be_bytes());
    digest.update(
        metadata
            .modified()
            .ok()
            .and_then(unix_nanos)
            .unwrap_or(0)
            .to_be_bytes(),
    );
    #[cfg(unix)]
    {
        digest.update(metadata.dev().to_be_bytes());
        digest.update(metadata.ino().to_be_bytes());
        digest.update(metadata.ctime().to_be_bytes());
        digest.update(metadata.ctime_nsec().to_be_bytes());
    }
    format!("{:x}", digest.finalize())
}

/// Membership is a directory-census fact. Persist this with the existing
/// traversal so a resumed page cannot certify a directory from another epoch.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct DirectoryCensus {
    directories: BTreeMap<String, String>,
    stable: bool,
}
impl DirectoryCensus {
    pub(super) fn local_diagnostic_counts(&self) -> (bool, u64) {
        (self.stable, self.directories.len() as u64)
    }

    pub(super) fn new() -> Self {
        Self {
            stable: true,
            ..Self::default()
        }
    }
    pub(super) fn invalidate_walk(&mut self) {
        self.stable = false;
    }
    pub(super) fn observe(&mut self, path: &Path, before: &fs::Metadata) {
        let witness = metadata_witness(before);
        if self.directories.len() >= MAX_HEADER_FILES
            && !self.directories.contains_key(&local_index_key(path))
        {
            self.stable = false;
            return;
        }
        let after = fs::symlink_metadata(path).ok();
        self.stable &= after.as_ref().is_some_and(|after| {
            after.is_dir() && !after.file_type().is_symlink() && metadata_witness(after) == witness
        });
        if self
            .directories
            .insert(local_index_key(path), witness.clone())
            .is_some_and(|previous| previous != witness)
        {
            self.stable = false;
        }
    }
    pub(super) fn contains(&self, path: &Path) -> bool {
        self.directories.contains_key(&local_index_key(path))
    }
    /// Census directories whose current metadata no longer matches their
    /// recorded witness: an entry was added, removed or renamed, or the
    /// directory itself was replaced or removed. Unchanged directories cost one
    /// `lstat` each and are never re-listed.
    pub(super) fn moved_directories(&self) -> Vec<PathBuf> {
        self.directories
            .iter()
            .filter(|(path, witness)| {
                fs::symlink_metadata(path).map_or(true, |current| {
                    !current.is_dir()
                        || current.file_type().is_symlink()
                        || metadata_witness(&current) != **witness
                })
            })
            .map(|(path, _)| PathBuf::from(path))
            .collect()
    }
    /// Re-certify one directory after a complete re-listing. The listing
    /// counts only if `before` (taken ahead of it) still matches the
    /// directory afterwards; otherwise the old witness stays, so `validate`
    /// keeps refusing joins in that home until a later refresh or walk.
    pub(super) fn refresh(&mut self, path: &Path, before: &fs::Metadata) -> bool {
        let witness = metadata_witness(before);
        let unchanged = fs::symlink_metadata(path).is_ok_and(|after| {
            after.is_dir() && !after.file_type().is_symlink() && metadata_witness(&after) == witness
        });
        if unchanged {
            self.directories.insert(local_index_key(path), witness);
        }
        unchanged
    }
    /// Drop a directory that no longer exists, with every census directory
    /// beneath it. A fresh walk would not list them either.
    pub(super) fn retire(&mut self, path: &Path) {
        self.directories
            .retain(|directory, _| !Path::new(directory).starts_with(path));
    }
    pub(super) fn validate(&self, home: &Path) -> Result<()> {
        anyhow::ensure!(self.stable, "Codex joining directory census is unproved");
        let mut count = 0;
        for (path, witness) in &self.directories {
            if !Path::new(path).starts_with(home) {
                continue;
            }
            count += 1;
            let current = fs::symlink_metadata(path)?;
            anyhow::ensure!(
                current.is_dir()
                    && !current.file_type().is_symlink()
                    && metadata_witness(&current) == *witness,
                "Codex joining directory membership changed"
            );
        }
        anyhow::ensure!(count > 0, "Codex joining lacks an owning directory census");
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct HeaderWitness {
    pub(super) candidate: CandidateFile,
    pub(super) owner: String,
    pub(super) custody_cause: Option<CodexZstCause>,
    /// True only on the archive member of a validated plain/archive twin; skip without decoding.
    pub(super) plain_twin: bool,
    pub(super) home: PathBuf,
    pub(super) created_unix_ms: Option<i64>,
    metadata: String,
    stamp: crate::transcript_acquisition::FileStamp,
}
impl HeaderWitness {
    pub(super) fn custody_current(&self) -> bool {
        fs::symlink_metadata(&self.candidate.path).is_ok_and(|stat| {
            stat.is_file()
                && !stat.file_type().is_symlink()
                && crate::transcript_acquisition::FileStamp::capture(stat)
                    .is_ok_and(|now| self.stamp.same_content(&now))
        })
    }
}

pub(super) fn member_home(root: &Path) -> PathBuf {
    member_home_ref(root).to_path_buf()
}
pub(super) fn member_home_ref(root: &Path) -> &Path {
    root.ancestors()
        .find(|path| {
            matches!(
                path.file_name().and_then(|value| value.to_str()),
                Some("sessions" | "archived_sessions")
            )
        })
        .and_then(Path::parent)
        .unwrap_or(root)
}
// One bounded secure acquisition path; semantic inventory and sampled-scope
// witnesses both use it. Only inventory performs native header decoding.
fn read_header_bytes(candidate: &CandidateFile) -> Result<(Vec<u8>, String, usize, FileStamp)> {
    refuse_compressed_codex(Some(&candidate.path), None, CodexZstCause::HeaderUnfunded)?;
    #[cfg(test)]
    tests::header_read_started(&candidate.path);
    let file = open_candidate_beneath_root(candidate)?;
    let before = file.metadata()?;
    anyhow::ensure!(before.is_file(), "Codex header is not a regular file");
    let stamp = FileStamp::capture(before.clone())?;
    let mut reader = BufReader::with_capacity(1024, file.take((MAX_HEADER_BYTES + 1) as u64));
    let mut bytes = Vec::new();
    #[cfg(all(test, unix))]
    header_cache_tests::READ_CALLS.with(|calls| calls.set(calls.get() + 1));
    reader.read_until(b'\n', &mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_HEADER_BYTES && bytes.last() == Some(&b'\n'),
        "Codex header exceeds its read bound"
    );
    let after = reader.get_ref().get_ref().metadata()?;
    let witness = metadata_witness(&before);
    anyhow::ensure!(
        stamp.same_content(&FileStamp::capture(after.clone())?)
            && metadata_witness(&after) == witness,
        HEADER_CHANGED_WHILE_READ
    );
    let read_bytes = (MAX_HEADER_BYTES + 1) - reader.get_ref().limit() as usize;
    Ok((bytes, witness, read_bytes, stamp))
}
type ReadHeader = (CachedHeader, String);
fn read_header(candidate: &CandidateFile) -> Result<ReadHeader> {
    let (bytes, witness, read_bytes, stamp) = read_header_bytes(candidate)?;
    #[cfg(test)]
    codex_zst_refusal_tests::jsonl_parse_attempted();
    let value: Value = serde_json::from_slice(&bytes)?;
    let meta =
        codex_session_meta_payload(&value).context("Codex first record is not a owning header")?;
    let owner = resolve_codex_identity_option(codex_identity_at(meta, &["id"]))
        .context("Codex header lacks ownership")?;
    let created_unix_ms = meta
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .and_then(|created| i64::try_from(created.unix_timestamp_nanos() / 1_000_000).ok());
    Ok((
        CachedHeader {
            stamp,
            owner,
            created_unix_ms,
            read_bytes,
        },
        witness,
    ))
}
/// Live rollouts are appended to while the inventory reads them. An append
/// that lands during the bounded first-record read moves the bracketing
/// witness without touching the header, and one such collision used to hold
/// every candidate on the page. Repeat the same bracketed read a few times;
/// each attempt still has to observe an unchanged object, so a replaced or
/// rewritten file, or an unreadable header, still fails. Only that race is
/// repeated; every other refusal is final on its first read.
const HEADER_READ_ATTEMPTS: usize = 3;
const HEADER_CHANGED_WHILE_READ: &str = "Codex header changed while read";
fn read_header_settled(candidate: &CandidateFile) -> (Result<ReadHeader>, usize) {
    let mut retried = 0;
    loop {
        match read_header(candidate) {
            Err(error)
                if retried + 1 < HEADER_READ_ATTEMPTS
                    && error.to_string() == HEADER_CHANGED_WHILE_READ =>
            {
                retried += 1
            }
            result => return (result, retried),
        }
    }
}
/// Metadata witness of one path without following a final symlink, or `None`
/// when it cannot be read (including when it is gone).
pub(super) fn path_witness(path: &Path) -> Option<String> {
    fs::symlink_metadata(path)
        .ok()
        .map(|metadata| metadata_witness(&metadata))
}
/// Raw header digest for a file whose owning header the native inventory has
/// already established. No extra decoded Value is retained or allocated.
pub(super) fn header_reduction_witness(
    candidate: &CandidateFile,
    archive: Option<&codex_compressed_input::ValidatedHeader>,
) -> Result<String> {
    if is_compressed_codex_rollout(Some(&candidate.path), None) {
        return archive.map(|header| header.digest.clone()).ok_or_else(|| {
            crate::local_resource_diagnostics::codex_zst_refused(CodexZstCause::HeaderInvalid);
            anyhow::anyhow!("archive header evidence unavailable")
        });
    }
    read_header_bytes(candidate).map(|(bytes, _, _, _)| format!("{:x}", Sha256::digest(bytes)))
}

/// RAM-only validated facts; candidate attribution and metadata witnesses are
/// rebuilt from the current secure object on every inventory step.
#[derive(Clone, Debug)]
pub(in crate::snapshots) struct CachedHeader {
    stamp: FileStamp,
    owner: String,
    created_unix_ms: Option<i64>,
    read_bytes: usize,
}
#[derive(Default)]
pub(in crate::snapshots) struct HeaderCache {
    entries: BTreeMap<String, CachedHeader>,
    // Immutable entry heaps, charged once at insertion via their field macros.
    // Keep the cursor's per-step walk independent of the roster population.
    heap_bytes: usize,
    // Pending count, drained into the next active Codex inventory carrier.
    evictions: usize,
}
impl HeaderCache {
    pub(in crate::snapshots) fn retain_roster(&mut self, paths: &VecDeque<PathBuf>) {
        // Pending paths preserve the roster's complete-string sort order.
        let heap_bytes = &mut self.heap_bytes;
        let evictions = &mut self.evictions;
        self.entries.retain(|key, header| {
            let keep = !is_compressed_codex_rollout(Some(Path::new(key)), None)
                && paths
                    .binary_search_by(|path| path.as_os_str().cmp(Path::new(key).as_os_str()))
                    .is_ok();
            if !keep {
                *evictions = evictions.saturating_add(1);
                *heap_bytes = heap_bytes.saturating_sub(Self::entry_heap(key.capacity(), header));
            }
            keep
        });
    }
    pub(in crate::snapshots) fn clear(&mut self) {
        self.evictions = self.evictions.saturating_add(self.entries.len());
        self.entries.clear();
        self.heap_bytes = 0;
    }
    fn take_evictions(&mut self) -> usize {
        std::mem::take(&mut self.evictions)
    }
    pub(in crate::snapshots) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(in crate::snapshots) fn admission_charge(
        key_capacity: usize,
        header: &CachedHeader,
    ) -> Option<usize> {
        crate::heap_layout_bound::tree_node_bytes::<String, CachedHeader>()?
            .checked_add(Self::entry_heap(key_capacity, header))
    }
    pub(in crate::snapshots) fn get(&self, key: &str) -> Option<CachedHeader> {
        #[cfg(all(test, unix))]
        header_cache_tests::cache_operation("get", key);
        if is_compressed_codex_rollout(Some(Path::new(key)), None) {
            return None;
        }
        self.entries.get(key).cloned()
    }
    pub(in crate::snapshots) fn refresh(&mut self, key: String, header: Option<CachedHeader>) {
        #[cfg(all(test, unix))]
        header_cache_tests::cache_operation("refresh", &key);
        if let Some((key, old)) = self.entries.remove_entry(&key) {
            self.evictions = self.evictions.saturating_add(1);
            self.heap_bytes = self
                .heap_bytes
                .saturating_sub(Self::entry_heap(key.capacity(), &old));
        }
        if let Some(header) =
            header.filter(|_| !is_compressed_codex_rollout(Some(Path::new(&key)), None))
        {
            if self.entries.len() < MAX_HEADER_FILES {
                self.heap_bytes = self
                    .heap_bytes
                    .saturating_add(Self::entry_heap(key.capacity(), &header));
                self.entries.insert(key, header);
            }
        }
    }
    fn entry_heap(key_capacity: usize, header: &CachedHeader) -> usize {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        let mut c = Counter::new(usize::MAX);
        c.add(key_capacity)
            .and_then(|()| header.heap_bound(&mut c))
            .map_or(usize::MAX, |()| c.bytes)
    }
    pub(in crate::snapshots) fn optional_bytes(&self) -> Option<usize> {
        crate::heap_layout_bound::tree_node_bytes::<String, CachedHeader>()?
            .checked_mul(self.entries.len())?
            .checked_add(self.heap_bytes)
    }
    pub(in crate::snapshots) fn charge(
        &self,
        c: &mut crate::heap_layout_bound::Counter,
    ) -> Option<()> {
        crate::heap_layout_bound::tree_nodes::<String, CachedHeader>(self.entries.len(), c)?;
        c.add(self.heap_bytes)
    }
}
crate::heap_layout_bound::fields!(CachedHeader; stamp, owner, created_unix_ms, read_bytes);
crate::heap_layout_bound::fields!(HeaderCache; entries, heap_bytes, evictions);

/// One small secure header read per existing native scan step. No transcript
/// or header Value is parked between steps.
#[derive(Clone, Debug)]
pub(super) struct HeaderInventory {
    roots: Vec<PathBuf>,
    pending: VecDeque<PathBuf>,
    pub(super) headers: Vec<HeaderWitness>,
    pub(super) directories: DirectoryCensus,
    pub(super) complete: bool,
    pub(super) custody_next: usize,
    pub(super) custody_after: Option<String>,
    pub(super) custody_done: bool,
    pub(super) custody_peak: usize,
    pub(super) custody_refused: bool,
    pub(super) custody_unknown: bool,
    pub(super) absence_held: BTreeSet<String>,
    pub(super) read_bytes: usize,
    pub(super) held_archives: BTreeSet<String>,
    pub(super) held_owners: BTreeSet<String>,
    pub(super) first_read_archives: BTreeSet<String>,
    pub(super) deferred_archives: BTreeSet<String>,
    /// Bound archives held by name with a resolved family sibling (value: twin).
    pub(super) family_held: BTreeMap<String, bool>,
    pub(super) archive_work: codex_compressed_input::HeaderWork,
    pub(super) reuse_hits: usize,
    pub(super) reuse_misses: usize,
    pub(super) bytes_avoided: usize,
    pub(super) reuse_evictions: usize,
    cache_pruned: bool,
    /// Roster files whose first record was refused, each with the metadata
    /// witness seen at the refusal (`None` when it could not be read). This is
    /// the evidence a held page waits on; see `CodexInventoryHold`.
    pub(super) refused: BTreeMap<String, Option<String>>,
    /// The inventory hit a population or read bound, or had no stable
    /// directory census. Only a fresh walk can change that.
    pub(super) bounded_out: bool,
}

/// A group's key in `HeaderInventory::groups`, which is also the order the
/// inventory reads groups in.
fn group_key(home: &Path, owner: &str) -> String {
    sha256_hex(&["codex_file_group:v1", &local_index_key(home), owner])
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum HeaderStep {
    Pending,
    Deferred,
    Complete,
}

impl HeaderInventory {
    pub(super) fn refresh_custody(&mut self, index: &ScanIndex) {
        for header in &mut self.headers {
            if let Some(cause) = index
                .files
                .get(&local_index_key(&header.candidate.path))
                .and_then(|entry| entry.codex_compressed_hold)
            {
                header.custody_cause = Some(cause);
            }
        }
    }
    pub(super) fn retry_custody_header(&mut self, at: usize) {
        let header = self.headers.remove(at);
        self.pending.push_front(header.candidate.path);
        for header in &mut self.headers {
            header.custody_cause = None;
        }
        self.custody_after = None;
        self.custody_next = 0;
        self.custody_done = false;
        // read_bytes is NOT reset: repeated real edits reach the existing bound.
        crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::OwnerUnproven);
    }
    /// 0a r3 (Lead B 2026-10-29): a bound archive X with a resolved sibling of
    /// its filename owner (a validated plain P, or another bound, invalid or
    /// validated archive) is held by name, quietly: X never decodes and P keeps
    /// publishing exactly as without X. Only unresolved (deferred) siblings
    /// defer X; once they resolve, X takes its one A1 read or is held.
    pub(super) fn classify_bound_archives(&mut self) {
        let owners_of =
            |key: &str| codex_session_id_candidates_from_path(&Path::new(key).with_extension(""));
        let mut plain = BTreeMap::<&str, Vec<&Path>>::new();
        let mut archives = BTreeMap::<String, usize>::new();
        for header in &self.headers {
            if is_compressed_codex_rollout(Some(&header.candidate.path), None) {
                *archives.entry(header.owner.clone()).or_default() += 1;
            } else {
                plain
                    .entry(&header.owner)
                    .or_default()
                    .push(&header.candidate.path);
            }
        }
        for key in self.first_read_archives.union(&self.held_archives) {
            for owner in owners_of(key) {
                *archives.entry(owner).or_default() += 1;
            }
        }
        let pending = self
            .deferred_archives
            .iter()
            .flat_map(|key| owners_of(key))
            .collect::<BTreeSet<_>>();
        let mut held = self.family_held.clone();
        let validated = self
            .headers
            .iter()
            .filter(|h| codex_archive_path(&h.candidate.path))
            .map(|h| local_index_key(&h.candidate.path))
            .collect::<BTreeSet<_>>();
        for key in self.first_read_archives.union(&validated) {
            let owners = owners_of(key);
            let name = Path::new(key).with_extension("");
            let name = name.file_name();
            if owners
                .iter()
                .any(|o| plain.contains_key(o.as_str()) || archives.get(o).is_some_and(|n| *n > 1))
            {
                let twin = owners
                    .iter()
                    .filter_map(|o| plain.get(o.as_str()))
                    .flatten()
                    .any(|p| p.file_name() == name);
                held.insert(key.clone(), twin);
            } else if owners.iter().any(|o| pending.contains(o)) {
                self.deferred_archives.insert(key.clone());
            }
        }
        // A held family owner never holds or refuses its plain member.
        self.held_owners = self
            .first_read_archives
            .iter()
            .filter(|key| !held.contains_key(*key))
            .chain(&self.deferred_archives)
            .chain(&self.held_archives)
            .flat_map(|key| owners_of(key))
            .collect();
        self.family_held = held;
    }
    pub(super) fn complete_for(&self, owner: Option<&String>) -> bool {
        self.complete
            && !owner.is_some_and(|owner| {
                self.held_owners.contains(owner)
                    || self.headers.iter().any(|h| {
                        &h.owner == owner
                            && h.custody_cause
                                .is_some_and(|cause| cause != CodexZstCause::FamilyUnproven)
                    })
            })
    }
    pub(super) fn new(
        roots: &[PathBuf],
        paths: &BTreeSet<String>,
        directories: Option<&DirectoryCensus>,
    ) -> Self {
        Self {
            roots: roots.to_vec(),
            pending: paths
                .iter()
                .take(MAX_HEADER_FILES + 1)
                .map(PathBuf::from)
                .collect(),
            headers: Vec::new(),
            directories: directories.cloned().unwrap_or_default(),
            complete: paths.len() <= MAX_HEADER_FILES
                && directories.is_some_and(|value| value.stable),
            read_bytes: 0,
            custody_next: 0,
            custody_after: None,
            custody_done: false,
            custody_peak: 0,
            custody_refused: false,
            custody_unknown: false,
            absence_held: BTreeSet::new(),
            held_archives: BTreeSet::new(),
            held_owners: BTreeSet::new(),
            first_read_archives: BTreeSet::new(),
            deferred_archives: BTreeSet::new(),
            family_held: BTreeMap::new(),
            archive_work: codex_compressed_input::HeaderWork::default(),
            reuse_hits: 0,
            reuse_misses: 0,
            bytes_avoided: 0,
            reuse_evictions: 0,
            cache_pruned: false,
            refused: BTreeMap::new(),
            bounded_out: paths.len() > MAX_HEADER_FILES
                || !directories.is_some_and(|value| value.stable),
        }
    }
    pub(super) fn content_unchanged(&self) -> bool {
        self.complete
            && self.pending.is_empty()
            && self.headers.iter().all(|header| {
                fs::symlink_metadata(&header.candidate.path)
                    .and_then(crate::transcript_acquisition::FileStamp::capture)
                    .is_ok_and(|stamp| header.stamp.same_content(&stamp))
            })
    }
    /// Inspect at most one quantum, before filtering. A partial feed cannot
    /// certify absence. The RAM cursor advances even when all archives reject.
    pub(super) fn retain_cached_archives(
        &mut self,
        index: &ScanIndex,
        paths: &BTreeSet<String>,
    ) -> Option<String> {
        use std::ops::Bound::{Excluded, Unbounded};
        let mut iter = match index.archive_pass.prep_after.as_ref() {
            Some(after) => paths.range((Excluded(after.clone()), Unbounded)),
            None => paths.range::<String, _>(..),
        };
        self.pending.clear();
        let mut last = None;
        for path in iter.by_ref().take(MAX_HEADER_FILES) {
            last = Some(path.clone());
            // Held-member exclusion precedes header-cache lookup (#878).
            let held = index
                .files
                .get(path)
                .and_then(|e| e.archive.as_ref())
                .is_some_and(|a| {
                    matches!(
                        a.disposition,
                        codex_compressed_input::ArchiveDisposition::Held { .. }
                    )
                });
            if !codex_archive_path(Path::new(path))
                || (!held && index.archive_header(Path::new(path)).is_some())
            {
                self.pending.push_back(PathBuf::from(path));
            }
        }
        // One extra probe detects debt; never truncate and claim complete.
        let remaining = iter.next().is_some();
        self.complete =
            index.archive_pass.prep_after.is_none() && !remaining && self.directories.stable;
        self.bounded_out = !self.complete;
        if remaining {
            last
        } else {
            None
        }
    }
    pub(super) fn owner_for_path(&self, path: &Path) -> Option<&str> {
        // Headers append in the pending BTreeSet<String> path order. Compare
        // whole path strings, not Path's component order (a.jsonl vs a/b.jsonl).
        self.headers
            .binary_search_by(|header| header.candidate.path.as_os_str().cmp(path.as_os_str()))
            .ok()
            .map(|index| self.headers[index].owner.as_str())
    }

    #[cfg(test)]
    pub(super) fn step(&mut self, metadata: &CodexTitleMetadata) -> bool {
        self.step_with_archive(metadata, &mut ScanIndex::default(), None) == HeaderStep::Complete
    }
    #[cfg(test)]
    pub(super) fn step_cached(
        &mut self,
        metadata: &CodexTitleMetadata,
        cache: Option<&sampled_scan::SharedCache>,
    ) -> bool {
        self.step_inner(metadata, &mut ScanIndex::default(), cache, None) == HeaderStep::Complete
    }
    pub(super) fn step_with_archive(
        &mut self,
        metadata: &CodexTitleMetadata,
        index: &mut ScanIndex,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
    ) -> HeaderStep {
        self.step_inner(metadata, index, cache.map(Arc::as_ref), cache)
    }
    fn step_inner(
        &mut self,
        metadata: &CodexTitleMetadata,
        index: &mut ScanIndex,
        cache: Option<&sampled_scan::SharedCache>,
        archive_cache: Option<&Arc<sampled_scan::SharedCache>>,
    ) -> HeaderStep {
        if !self.cache_pruned {
            self.cache_pruned = true;
            if let Some(cache) = cache {
                cache.with_cursor(|cursor| cursor.headers.retain_roster(&self.pending));
            }
        }
        if let Some(cache) = cache {
            self.reuse_evictions = self.reuse_evictions.saturating_add(
                cache
                    .with_cursor(|cursor| cursor.headers.take_evictions())
                    .unwrap_or(0),
            );
        }
        // Every deferred path stays in custody for the next page, after plain work.
        if self
            .pending
            .front()
            .is_some_and(|path| self.deferred_archives.contains(&local_index_key(path)))
        {
            return HeaderStep::Complete;
        }
        let Some(path) = self.pending.pop_front() else {
            return HeaderStep::Complete;
        };
        if self.read_bytes >= MAX_HEADER_READ_BYTES || self.headers.len() >= MAX_HEADER_FILES {
            self.complete = false;
            self.bounded_out = true;
            self.pending.clear();
            return HeaderStep::Complete;
        }
        let Some(scan_root) = self
            .roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
        else {
            self.complete = false;
            self.bounded_out = true;
            return HeaderStep::Pending;
        };
        // Held plain files still need the existing cold owning-header read:
        // group/owner gates scope their custody hold without stalling siblings.
        // Warm facts must not supply or refresh that evidence while held.
        let key = local_index_key(&path);
        if index
            .files
            .get(&key)
            .is_some_and(|entry| entry.codex_compressed_hold.is_some())
        {
            return HeaderStep::Pending;
        }
        if self.held_archives.contains(&key) {
            return HeaderStep::Pending;
        }
        let compressed = is_compressed_codex_rollout(Some(&path), None);
        let decode_held = index.decode_holds_file(&key);
        if compressed && decode_held {
            self.complete = false;
            self.refused.insert(key, path_witness(&path));

            return HeaderStep::Pending;
        }
        let cache = cache.filter(|_| !decode_held);
        // #878 composition: custody is consulted before any header fact lookup.
        if let Some(cause) = index
            .files
            .get(&key)
            .and_then(|e| e.archive.as_ref())
            .and_then(|a| match a.disposition {
                codex_compressed_input::ArchiveDisposition::Held { cause } => Some((a, cause)),
                _ => None,
            })
            .and_then(|(a, cause)| {
                fs::symlink_metadata(&path)
                    .ok()
                    .and_then(|m| crate::transcript_acquisition::FileStamp::capture(m).ok())
                    .filter(|stamp| a.stamp.same_content(stamp))
                    .map(|_| cause)
            })
        {
            if cause == CodexZstCause::FamilyUnproven {
                self.family_held.insert(key, false);
            } else {
                self.held_archives.insert(key);
            }
            return HeaderStep::Pending;
        }

        let mut excluded = false;
        let mut deferred = false;
        let result = (|| -> Result<Option<HeaderWitness>> {
            let stat = fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                stat.is_file() && !stat.file_type().is_symlink(),
                "invalid Codex header member"
            );
            let seconds = stat.modified().ok().and_then(unix_seconds).unwrap_or(0);
            let mut candidate = CandidateFile {
                physical_identity: None,
                scan_root,
                path,
                size_bytes: stat.len(),
                modified_unix_seconds: seconds,
                modified_unix_nanos: stat
                    .modified()
                    .ok()
                    .and_then(unix_nanos)
                    .unwrap_or(seconds.saturating_mul(1_000_000_000)),
                source_file_fingerprint: String::new(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: String::new(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
            };
            prepare_owned_scan_candidate(
                SnapshotSource::Codex,
                &mut candidate,
                metadata,
                &ClaudeTitleMetadata::default(),
                None,
            );
            if compressed {
                // Archives have their own FD-bound evidence and never consult
                // or populate the optional plain header fact cache.
                let before = self.archive_work.physical_bytes;
                let result = index.inventory_archive_header(
                    &candidate,
                    archive_cache,
                    &mut self.archive_work,
                );
                excluded = index
                    .files
                    .get(&key)
                    .and_then(|e| e.archive.as_ref())
                    .is_some_and(|a| a.invalid_header(&candidate.path, &stat));
                self.read_bytes = self
                    .read_bytes
                    .saturating_add((self.archive_work.physical_bytes - before) as usize);
                let header = match result? {
                    codex_compressed_input::HeaderRead::Validated(header) => header,
                    codex_compressed_input::HeaderRead::BoundReached => {
                        return Ok(None);
                    }
                    codex_compressed_input::HeaderRead::Deferred => {
                        deferred = true;
                        return Ok(None);
                    }
                };
                let stamp = index
                    .files
                    .get(&key)
                    .and_then(|e| e.archive.as_ref())
                    .context("archive header stamp unavailable")?
                    .stamp
                    .clone();
                return Ok(Some(HeaderWitness {
                    plain_twin: false,
                    custody_cause: None,
                    home: member_home(&candidate.scan_root),
                    candidate,
                    owner: header.owner,
                    created_unix_ms: header.created_unix_ms,
                    metadata: metadata_witness(&stat),
                    stamp,
                }));
            }
            self.reuse_misses += 1;
            let mut reused = None;
            if let Some(cached) = cache.and_then(|cache| {
                cache
                    .with_cursor(|cursor| cursor.headers.get(&key))
                    .flatten()
            }) {
                let current = open_candidate_beneath_root(&candidate)?.metadata()?;
                let stamp = FileStamp::capture(current.clone())?;
                // Non-Unix stamps have no object identity; length alone
                // cannot authorize reuse of owning-header facts.
                if cached.stamp.same_object(&stamp) && cached.stamp.same_content(&stamp) {
                    self.reuse_hits += 1;
                    self.reuse_misses -= 1;
                    self.bytes_avoided = self.bytes_avoided.saturating_add(cached.read_bytes);
                    reused = Some((cached, metadata_witness(&current)));
                }
            }
            let (facts, witness) = match reused {
                Some(header) => header,
                None => {
                    if let Some(cache) = cache {
                        cache.refresh_header(key.clone(), None);
                    }
                    let (header, retried) = read_header_settled(&candidate);
                    // Each abandoned attempt may consume its whole prefix.
                    self.read_bytes = self
                        .read_bytes
                        .saturating_add(retried.saturating_mul(MAX_HEADER_BYTES + 1));
                    let (facts, witness) = header?;
                    self.read_bytes = self.read_bytes.saturating_add(facts.read_bytes);
                    if let Some(cache) = cache {
                        cache.refresh_header(key.clone(), Some(facts.clone()));
                    }
                    (facts, witness)
                }


            };
            Ok(Some(HeaderWitness {
                custody_cause: None,
                plain_twin: false,
                home: member_home(&candidate.scan_root),
                candidate,
                owner: facts.owner,
                created_unix_ms: facts.created_unix_ms,
                metadata: witness,
                stamp: facts.stamp,
            }))
        })();
        match result {
            Ok(Some(header)) => self.headers.push(header),
            Ok(None) => {
                self.held_owners
                    .extend(codex_session_id_candidates_from_path(
                        &Path::new(&key).with_extension(""),
                    ));
                if deferred {
                    self.pending.push_back(PathBuf::from(&key));
                    self.deferred_archives.insert(key);
                    return HeaderStep::Deferred;
                }
                self.first_read_archives.insert(key);
            }
            Err(_) if excluded => {
                self.held_owners
                    .extend(codex_session_id_candidates_from_path(
                        &Path::new(&key).with_extension(""),
                    ));
                self.held_archives.insert(key);
            }
            Err(_) => {
                if !compressed {
                    if let Some(cache) = cache {
                        cache.refresh_header(key.clone(), None);
                    }
                }
                self.complete = false;
                // A failed read may have consumed its whole bounded prefix.
                if !compressed {
                    self.read_bytes = self.read_bytes.saturating_add(MAX_HEADER_BYTES + 1);
                }
                let witness = path_witness(Path::new(&key));
                self.refused.insert(key, witness);
            }
        }
        if self.read_bytes > MAX_HEADER_READ_BYTES {
            self.complete = false;
            self.bounded_out = true;
        }
        HeaderStep::Pending
    }
    pub(super) fn groups(&self) -> BTreeMap<String, Group> {
        let mut groups = BTreeMap::<String, Group>::new();
        for header in self
            .headers
            .iter()
            .filter(|h| !self.member_held(&h.candidate.path))
        {
            if codex_archive_path(&header.candidate.path) { continue; }
            let key = group_key(&header.home, &header.owner);
            groups
                .entry(key)
                .or_insert_with(|| Group {
                    owner: header.owner.clone(),
                    home: header.home.clone(),
                    members: Vec::new(),
                    live: None,
                })
                .members
                .push(header.candidate.clone());
        }
        groups
    }
    #[cfg(test)]
    pub(super) fn validate_membership(&self, owner: &str, home: &Path) -> Result<()> {
        self.validate_memberships(&BTreeMap::from([(
            home.to_path_buf(),
            BTreeSet::from([owner.to_owned()]),
        )]))
        .map(|_| ())
    }
    fn validate_memberships(&self, owners: &BTreeMap<PathBuf, BTreeSet<String>>) -> Result<usize> {
        anyhow::ensure!(
            self.complete,
            "Codex joining header inventory is incomplete"
        );
        for home in owners.keys() {
            self.directories.validate(home)?;
        }
        let mut checked_headers = 0;
        for header in self
            .headers
            .iter()
            .filter(|h| !self.member_held(&h.candidate.path))
        {
            let Some(selected) = owners.get(&header.home) else {
                continue;
            };
            checked_headers += 1;
            let stat = fs::symlink_metadata(&header.candidate.path)?;
            if metadata_witness(&stat) == header.metadata {
                continue;
            }
            if is_compressed_codex_rollout(Some(&header.candidate.path), None) {
                anyhow::ensure!(
                    header
                        .stamp
                        .same_content(&crate::transcript_acquisition::FileStamp::capture(stat)?),
                    "archive header stamp changed"
                );
                continue;
            }
            let (current, _) = read_header(&header.candidate)?;
            anyhow::ensure!(
                current.owner == header.owner
                    || (!selected.contains(&current.owner) && !selected.contains(&header.owner)),
                "Codex joining header ownership changed"
            );
        }
        Ok(checked_headers)
    }
}
crate::heap_layout_bound::fields!(DirectoryCensus; directories, stable);
crate::heap_layout_bound::fields!(HeaderWitness; plain_twin, custody_cause, candidate, owner, home, created_unix_ms, metadata, stamp);
crate::heap_layout_bound::fields!(HeaderInventory; custody_next, absence_held, custody_unknown, custody_after, custody_done, custody_peak, custody_refused, roots, pending, headers, directories, complete, read_bytes, held_archives, held_owners, archive_work, reuse_hits, reuse_misses, bytes_avoided, reuse_evictions, cache_pruned, refused, bounded_out, first_read_archives, deferred_archives, family_held);



#[derive(Clone, Debug)]
pub(super) struct Group {
    pub(super) owner: String,
    pub(super) home: PathBuf,
    pub(super) members: Vec<CandidateFile>,
    /// A paged group's live member (index key) and the grant its sealed-prefix
    /// certificate passed with (S12): validation then accepts that member's
    /// growth past the frozen extent on the same object, like `finish`.
    pub(super) live: Option<(String, sampled_scan::codex_cursor::SealedPrefix)>,
}
#[derive(Clone, Debug)]
pub(super) struct Validation {
    pub(super) inventory: HeaderInventory,
    pub(super) groups: Vec<Group>,
}
impl Validation {
    pub(super) fn validate_all(&self) -> Result<usize> {
        self.validate(
            &self
                .groups
                .iter()
                .map(|group| group.owner.clone())
                .collect(),
        )
    }
    pub(super) fn validate(&self, owners: &BTreeSet<String>) -> Result<usize> {
        let mut homes = BTreeMap::<PathBuf, BTreeSet<String>>::new();
        for group in &self.groups {
            if owners.contains(&group.owner) {
                homes
                    .entry(group.home.clone())
                    .or_default()
                    .insert(group.owner.clone());
            }
        }
        // One fresh roster check per home/boundary, independent of group count.
        // Never cache this result across capture, network or checkpoint boundaries.
        let checked_headers = self.inventory.validate_memberships(&homes)?;
        for group in &self.groups {
            if !owners.contains(&group.owner) {
                continue;
            }
            for member in &group.members {
                let mut opened = member.clone();
                let file = open_candidate_file(SnapshotSource::Codex, &mut opened)?;
                let granted = group.live.as_ref().is_some_and(|(key, prefix)| {
                    *key == local_index_key(&member.path) && prefix.holds(&file)
                });
                anyhow::ensure!(
                    granted || opened.opened_object_identity == member.opened_object_identity,
                    "Codex joined member changed after replay"
                );
            }
        }
        Ok(checked_headers)
    }
}
crate::heap_layout_bound::fields!(Group; owner, home, members, live);
crate::heap_layout_bound::fields!(Validation; inventory, groups);

pub(super) fn captured_join(witness: &str) -> String {
    format!("codex_captured_join:v1:{witness}")
}
pub(super) fn valid_captured_join(value: &str) -> bool {
    value
        .strip_prefix("codex_captured_join:v1:")
        .is_some_and(valid_codex_protected_owner)
}
pub(super) fn member_set_witness(members: &[CandidateFile]) -> String {
    let sorted = members
        .iter()
        .map(|member| {
            (
                local_index_key(&member.path),
                member.source_file_fingerprint.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut digest = Sha256::new();
    digest.update(b"codex_joined_member_set:v1\0");
    for (path, fingerprint) in sorted {
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update(fingerprint.as_bytes());
    }
    format!("{:x}", digest.finalize())
}
#[derive(Clone, Debug)]
pub(crate) struct LegacyBaseline {
    pub(crate) owner: String,
    pub(crate) index_key: String,
    pub(crate) expected: String,
    pub(crate) snapshots: Vec<SnapshotItem>,
}
crate::heap_layout_bound::fields!(LegacyBaseline; owner, index_key, expected, snapshots);
const RECEIPT_VERSION: u16 = 1;
const MAX_APPLIED_TIERS: usize = 512;
pub(super) const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
/// Previous application evidence, not provider billing truth. Only hashes of
/// physical records/context and the applied priority provenance are retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedTierReceipt {
    version: u16,
    derivation: String,
    scope: String,
    records: usize,
    prefix_digest: String,
    tiers: BTreeMap<String, String>,
}
pub(super) fn deserialize_receipt<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<AppliedTierReceipt>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    // A future/malformed local receipt must hold its file, rather than make
    // the ordinary index decoder discard every protected file as corruption.
    Ok(Some(serde_json::from_value(value).unwrap_or_else(|_| {
        AppliedTierReceipt {
            version: u16::MAX,
            derivation: String::new(),
            scope: String::new(),
            records: 0,
            prefix_digest: String::new(),
            tiers: BTreeMap::new(),
        }
    })))
}
impl AppliedTierReceipt {
    pub(super) fn retained_bytes(&self) -> usize {
        struct Bytes(usize);
        impl std::io::Write for Bytes {
            fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.saturating_add(value.len());
                Ok(value.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut bytes = Bytes(0);
        if serde_json::to_writer(&mut bytes, self).is_err() {
            return usize::MAX;
        }
        bytes.0
    }
    pub(super) fn covered_by(&self, previous: &Self) -> bool {
        self.version == previous.version
            && self.derivation == previous.derivation
            && self.scope == previous.scope
            && self
                .tiers
                .iter()
                .all(|(key, source)| previous.tiers.get(key) == Some(source))
    }
}
pub(super) fn receipt_state(entry: Option<&ScanIndexEntry>) -> (Option<AppliedTierReceipt>, bool) {
    let Some(entry) = entry else {
        return (None, false);
    };
    let missing = (entry.codex_captured_tier_receipt_required
        && entry.codex_captured_tier_receipt.is_none())
        || (entry.codex_applied_tier_receipt_required
            && entry.codex_applied_tier_receipt.is_none())
        || (entry.codex_captured_uncommitted
            && entry.codex_captured_tier_receipt.is_none()
            && entry.codex_captured_joined_member_set.is_none());
    let required = missing
        || entry.codex_captured_tier_receipt_required
        || entry.codex_applied_tier_receipt_required;
    if missing {
        return (None, required);
    }
    (
        entry
            .codex_captured_tier_receipt
            .clone()
            .or_else(|| entry.codex_applied_tier_receipt.clone()),
        required,
    )
}
#[derive(Clone)]
pub(super) struct TierReplay {
    previous: Option<AppliedTierReceipt>,
    digest: ContentDigest,
    records: usize,
    matched: BTreeSet<String>,
    tiers: BTreeMap<String, String>,
    scope: String,
    prefix_matched: bool,
    invalid: bool,
    /// The group proof while this replay reads a joined member.
    pub(super) join: Option<Box<StreamProof>>,
}
impl TierReplay {
    pub(super) fn new(previous: Option<AppliedTierReceipt>, required: bool, scope: String) -> Self {
        let invalid = previous.as_ref().is_some_and(|receipt| {
            receipt.version != RECEIPT_VERSION
                || receipt.derivation != SnapshotSource::Codex.parser_version()
                || receipt.scope != scope
                || receipt.records == 0
                || !is_sha256_hex(&receipt.prefix_digest)
                || receipt.tiers.len() > MAX_APPLIED_TIERS
                || receipt.tiers.iter().any(|(key, source)| {
                    !is_sha256_hex(key)
                        || source.is_empty()
                        || source.len() > 64
                        || !source
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._[]".contains(&byte))
                })
        }) || (required && previous.is_none());
        Self {
            previous,
            digest: ContentDigest(Sha256::new()),
            records: 0,
            matched: BTreeSet::new(),
            tiers: BTreeMap::new(),
            scope,
            prefix_matched: false,
            invalid,
            join: None,
        }
    }
    pub(super) fn observe(&mut self, value: &Value) {
        if let Some(join) = self.join.as_mut() {
            join.observe(value);
        }
        self.records += 1;
        if serde_json::to_writer(&mut self.digest, value).is_err() {
            self.invalid = true;
        }
        self.digest.0.update(b"\n");
        if let Some(previous) = &self.previous {
            if self.records == previous.records {
                self.prefix_matched =
                    format!("{:x}", self.digest.0.clone().finalize()) == previous.prefix_digest;
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn selector(
        &mut self,
        value: &Value,
        selector: &mut SelectorCapture,
        current: &SelectorCapture,
        model: Option<&str>,
        effort: Option<&str>,
        turn: Option<&str>,
    ) -> Option<(String, String)> {
        // Older cumulative-only rows still have an exact physical record and
        // ordinal. Retaining that digest does not infer response ownership.
        let event = codex_usage_event_identity(value).unwrap_or_else(|| {
            let mut digest = ContentDigest(Sha256::new());
            let _ = serde_json::to_writer(&mut digest, value);
            format!("physical_record:{:x}", digest.0.finalize())
        });
        let mut context = current.clone();
        context.merge(selector.clone());
        context.context.remove("service_tier");
        context.sources.remove("service_tier");
        let mut context_digest = ContentDigest(Sha256::new());
        let _ = serde_json::to_writer(
            &mut context_digest,
            &(context.context, context.sources, model, effort, turn),
        );
        let key = sha256_hex(&[
            "codex_applied_tier:v1",
            &self.records.to_string(),
            &event,
            &format!("{:x}", context_digest.0.finalize()),
        ]);
        if let Some(previous) = &self.previous {
            if self.records <= previous.records {
                if let Some(source) = previous.tiers.get(&key) {
                    // This restoration is exact-record scoped. Prefix validation
                    // at EOF is mandatory before any body may be emitted.
                    if !selector.context.contains_key("service_tier")
                        && !current.context.contains_key("service_tier")
                    {
                        selector.insert("service_tier", "priority".into(), source);
                    }
                }
            }
        }
        let tier = selector
            .context
            .get("service_tier")
            .or_else(|| current.context.get("service_tier"));
        if tier.map(String::as_str) == Some("priority") {
            let source = selector
                .sources
                .get("service_tier")
                .or_else(|| current.sources.get("service_tier"))?
                .clone();
            Some((key, source))
        } else {
            None
        }
    }
    pub(super) fn admitted(&mut self, tier: Option<(String, String)>) {
        if let Some((key, source)) = tier {
            if source.len() > 64 || self.tiers.len() >= MAX_APPLIED_TIERS {
                self.invalid = true;
                return;
            }
            self.matched.insert(key.clone());
            self.tiers.insert(key, source);
        }
    }
    /// S10: the parser admitted usage from `value` (after actual admission),
    /// under the accumulator's counting version `v2`.
    pub(super) fn admitted_usage(
        &mut self,
        value: &Value,
        from_last: bool,
        identity: Option<&str>,
        turn: Option<&str>,
        v2: bool,
    ) {
        if let Some(join) = self.join.as_mut() {
            join.decide_v2(v2);
            join.admitted_usage(value, from_last, identity, turn);
        }
    }
    /// A sampled prefix cannot authorize a new protected receipt. The host
    /// reopens and fully replays before calling finish when this is true.
    pub(super) fn has_protected_tiers(&self) -> bool {
        !self.tiers.is_empty()
    }
    pub(super) fn finish(self) -> Result<Option<AppliedTierReceipt>> {
        anyhow::ensure!(
            !self.invalid,
            "Codex applied-tier receipt is unavailable or exceeds its bound"
        );
        if let Some(previous) = &self.previous {
            anyhow::ensure!(
                self.prefix_matched && previous.tiers.keys().all(|key| self.matched.contains(key)),
                "Codex protected pricing prefix or contribution context changed"
            );
        }
        if self.tiers.is_empty() {
            return Ok(None);
        }
        Ok(Some(AppliedTierReceipt {
            version: RECEIPT_VERSION,
            derivation: SnapshotSource::Codex.parser_version().into(),
            scope: self.scope,
            records: self.records,
            prefix_digest: format!("{:x}", self.digest.0.finalize()),
            tiers: self.tiers,
        }))
    }
}
crate::heap_layout_bound::fields!(AppliedTierReceipt; version, derivation, scope, records, prefix_digest, tiers);
crate::heap_layout_bound::fields!(TierReplay; previous, digest, records, matched, tiers, scope, prefix_matched, invalid, join);
/// Named group refusals (§i). The discriminant is the RAM counter slot of
/// `codex_join_terminal_debt`. Every reason but `ProbeBudgetOrder` is
/// terminal debt for the attempt (outcome R): the members are disclosed as
/// settleable residue, never as an unreadable file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum JoinRefusal {
    Overlap,
    Gap,
    Corrupt,
    CumulativeOnly,
    UiShape,
    UiOnlyMember,
    UiUnmatched,
    UiRepeatUnproven,
    OrdinalRestart,
    HistoryBase,
    AmbiguousPredecessor,
    ForkedFromOtherSession,
    CreatedThreadGroup,
    MixedOrdinal,
    EqualBeforeTie,
    CandidateCopy,
    V2UiOnlyTurn,
    V2UnboundUi,
    /// A `history_base.thread_id` names no member of this owner's group.
    MissingPredecessor,
    /// A chain refusal (`Gap`, `Overlap`) of a legacy group replayed in
    /// chronological order because its probes exceeded their budget (R1-M1,
    /// R2-N2): the order may be our own artifact, so it is strict, never
    /// settleable or memoized.
    ProbeBudgetOrder,
}
pub(super) const JOIN_REFUSALS: usize = 20;
impl JoinRefusal {
    pub(super) fn slot(self) -> usize {
        self as usize
    }
    /// Growth of the live member may cure these (§d.4). Every other reason,
    /// and any reason whose first failing member is sealed, is append-incurable.
    pub(super) fn append_curable(self) -> bool {
        matches!(
            self,
            Self::Gap
                | Self::UiOnlyMember
                | Self::UiUnmatched
                | Self::UiRepeatUnproven
                | Self::V2UiOnlyTurn
        )
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for JoinRefusal {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// First eight bytes of SHA-256: the exact compact set element. A collision
/// errs toward `Overlap`, never toward admission.
fn compact(tag: &[u8], value: &str) -> u64 {
    let mut digest = Sha256::new();
    digest.update(tag);
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

/// Header-derived facts of one canonical member position (§a.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct MemberPlan {
    /// Header ordinal (ordinal groups only): the member's first ordinal.
    pub(super) first: Option<u64>,
    /// Ordinals a later continuation binds to; their record starts are kept.
    pub(super) watch: Vec<u64>,
    /// `(predecessor position, end_ordinal_exclusive, end_byte_offset)`.
    pub(super) binding: Option<(usize, u64, u64)>,
    /// A duplicate origin that must end neutral (F1).
    pub(super) stub: bool,
}
crate::heap_layout_bound::fields!(MemberPlan; first, watch, binding, stub);

/// What a completed member left for later bindings.
#[derive(Clone, Debug, Default)]
struct MemberSeen {
    last: Option<u64>,
    end: u64,
    starts: Vec<(u64, u64)>,
}
crate::heap_layout_bound::fields!(MemberSeen; last, end, starts);

#[derive(Clone, Debug, Default)]
struct MemberState {
    records: u64,
    natives: u64,
    admissions: u64,
    last_after: Option<Tokens>,
    balance: BTreeMap<Tokens, i64>,
    repeat: BTreeMap<Tokens, u64>,
    last_admitted: Option<Tokens>,
    native_since_admit: bool,
    usage_shaped: bool,
    next_ordinal: Option<u64>,
    last_ordinal: Option<u64>,
    starts: Vec<(u64, u64)>,
}

/// The group proof, fed inside the one native replay: the native side in
/// `TierReplay::observe`, the UI side by the parser admission tap (S10)
/// after actual admission. It moves from member to member with the replay.
/// Only compact identities, counters and per-member tuple balances are kept.
#[derive(Clone, Debug)]
pub(super) struct StreamProof {
    owner: String,
    v2: bool,
    plans: Vec<MemberPlan>,
    seen: Vec<MemberSeen>,
    position: usize,
    member: MemberState,
    responses: BTreeSet<u64>,
    ui: BTreeSet<u64>,
    /// `after` of the last native of the previous usage-bearing member.
    chain: Tokens,
    refusal: Option<(JoinRefusal, usize)>,
    /// Start offset of the record the reader delivers in this step.
    record_start: u64,
    turn: Option<u64>,
    native_turns: BTreeSet<u64>,
    ui_turns: BTreeSet<u64>,
    unbound_ui: bool,
}

/// Heap bytes of a std B-tree of `len` inline entries (R2-M4). Every
/// non-root node holds at least `MIN_LEN = 5` of its 11 slots (std
/// `btree/map.rs` invariant) and every entry lives in exactly one node, so a
/// tree has at most `len / 5 + 1` nodes. Each is charged as a full internal
/// node (11 slots, 12 edges) plus the same 256-byte header slack as
/// `tree_nodes`, which charges one such node per entry (five times this).
fn proof_tree_bytes<K, V>(len: usize) -> Option<usize> {
    let node = 256usize
        .checked_add(12 * size_of::<usize>())?
        .checked_add(11usize.checked_mul(size_of::<K>().checked_add(size_of::<V>())?)?)?;
    (len / 5).checked_add(1)?.checked_mul(node)
}

impl crate::heap_layout_bound::HeapLayoutBound for StreamProof {
    // Fixed visits per walk: the compact sets and balance maps are charged by
    // length (`proof_tree_bytes`), never element by element, so a large
    // group stays within one walk's visit limit and its bytes are counted.
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        self.owner.heap_bound(c)?;
        self.plans.heap_bound(c)?;
        self.seen.heap_bound(c)?;
        self.member.starts.heap_bound(c)?;
        let trees = [
            proof_tree_bytes::<Tokens, i64>(self.member.balance.len())?,
            proof_tree_bytes::<Tokens, u64>(self.member.repeat.len())?,
            proof_tree_bytes::<u64, ()>(self.responses.len())?,
            proof_tree_bytes::<u64, ()>(self.ui.len())?,
            proof_tree_bytes::<u64, ()>(self.native_turns.len())?,
            proof_tree_bytes::<u64, ()>(self.ui_turns.len())?,
        ];
        c.add(
            trees
                .iter()
                .try_fold(0usize, |sum, bytes| sum.checked_add(*bytes))?,
        )
    }
}

impl StreamProof {
    pub(super) fn new(owner: String, v2: bool, plans: Vec<MemberPlan>) -> Self {
        Self {
            owner,
            v2,
            plans,
            seen: Vec::new(),
            position: 0,
            member: MemberState::default(),
            responses: BTreeSet::new(),
            ui: BTreeSet::new(),
            chain: Tokens::default(),
            refusal: None,
            record_start: 0,
            turn: None,
            native_turns: BTreeSet::new(),
            ui_turns: BTreeSet::new(),
            unbound_ui: false,
        }
    }

    /// The first refusal and the canonical position of its failing member.
    pub(super) fn refusal(&self) -> Option<(JoinRefusal, usize)> {
        self.refusal
    }

    fn refuse(&mut self, reason: JoinRefusal) {
        if self.refusal.is_none() {
            self.refusal = Some((reason, self.position));
        }
    }

    pub(super) fn set_record_start(&mut self, offset: u64) {
        self.record_start = offset;
    }

    /// Open canonical position `position`. A continuation binds only when its
    /// predecessor (read before it) holds a record with ordinal `E` starting
    /// at `end_byte_offset`, or ended exactly there with `last + 1 == E`.
    pub(super) fn begin_member(&mut self, position: usize) {
        self.position = position;
        self.member = MemberState {
            next_ordinal: self.plans.get(position).and_then(|plan| plan.first),
            ..MemberState::default()
        };
        self.turn = None;
        let Some((predecessor, end, offset)) =
            self.plans.get(position).and_then(|plan| plan.binding)
        else {
            return;
        };
        let bound = self.seen.get(predecessor).is_some_and(|seen| {
            seen.starts.contains(&(end, offset))
                || (seen.last.and_then(|last| last.checked_add(1)) == Some(end)
                    && seen.end == offset)
        });
        if !bound {
            self.refuse(JoinRefusal::HistoryBase);
        }
    }

    pub(super) fn observe(&mut self, value: &Value) {
        if self.refusal.is_some() {
            return;
        }
        if let Err(reason) = self.observe_record(value) {
            self.refuse(reason);
        }
    }

    fn observe_record(&mut self, value: &Value) -> std::result::Result<(), JoinRefusal> {
        self.member.records += 1;
        let first = self.member.records == 1;
        match codex_session_meta_payload(value) {
            Some(meta) => {
                if !first {
                    return Err(JoinRefusal::Corrupt);
                }
                let owner = resolve_codex_identity_option(codex_identity_at(meta, &["id"]));
                if owner.as_deref() != Some(self.owner.as_str()) {
                    return Err(JoinRefusal::Overlap);
                }
            }
            None if first => return Err(JoinRefusal::Corrupt),
            None => {}
        }
        let ordinal_member = self
            .plans
            .get(self.position)
            .is_some_and(|plan| plan.first.is_some());
        match (ordinal_member, value.get("ordinal")) {
            (true, None) => return Err(JoinRefusal::Corrupt),
            (true, Some(ordinal)) => {
                let ordinal = ordinal.as_u64().ok_or(JoinRefusal::Corrupt)?;
                if Some(ordinal) != self.member.next_ordinal {
                    return Err(JoinRefusal::Corrupt);
                }
                self.member.next_ordinal = ordinal.checked_add(1);
                self.member.last_ordinal = Some(ordinal);
                if self.plans[self.position].watch.contains(&ordinal) {
                    self.member.starts.push((ordinal, self.record_start));
                }
            }
            (false, Some(_)) => return Err(JoinRefusal::MixedOrdinal),
            (false, None) => {}
        }
        // The parser's running turn: `turn_context` or a payload turn id.
        if let Some(turn) = string_at(value, &["turn_context", "payload", "turn_id"])
            .or_else(|| string_at(value, &["payload", "turn_id"]))
        {
            self.turn = Some(compact(b"t:", &turn));
        }
        let native = string_eq_at(value, &["type"], "token_usage_record");
        if native
            || codex_total_usage(value).is_some_and(|usage| !usage.is_zero())
            || codex_last_usage(value).is_some_and(|usage| !usage.is_zero())
        {
            self.member.usage_shaped = true;
        }
        if native {
            self.observe_native(value)?;
        }
        Ok(())
    }

    fn observe_native(&mut self, value: &Value) -> std::result::Result<(), JoinRefusal> {
        let payload = value.get("payload").ok_or(JoinRefusal::Corrupt)?;
        let thread = payload
            .get("thread_id")
            .and_then(Value::as_str)
            .ok_or(JoinRefusal::Corrupt)?;
        if resolve_codex_identity(thread) != self.owner {
            return Err(JoinRefusal::Overlap);
        }
        let response = payload
            .get("response_id")
            .and_then(Value::as_str)
            .filter(|response| !response.is_empty() && response.len() <= 256)
            .ok_or(JoinRefusal::Corrupt)?;
        let usage = payload
            .get("usage")
            .and_then(Tokens::read)
            .ok_or(JoinRefusal::Corrupt)?;
        let after = payload
            .get("thread_token_usage")
            .and_then(Tokens::read)
            .ok_or(JoinRefusal::Corrupt)?;
        let before = after.before(usage).ok_or(JoinRefusal::Corrupt)?;
        if !self.responses.insert(compact(b"r:", response)) {
            return Err(JoinRefusal::Overlap);
        }
        match self.member.last_after {
            // A non-monotone counter inside one member is a reset.
            Some(previous) if previous != before => return Err(JoinRefusal::Gap),
            Some(_) => {}
            None if before != self.chain => {
                return Err(if before.covers(self.chain) {
                    JoinRefusal::Gap
                } else {
                    JoinRefusal::Overlap
                });
            }
            None => {}
        }
        let member = &mut self.member;
        member.last_after = Some(after);
        member.natives += 1;
        member.native_since_admit = true;
        let balance = member.balance.entry(usage).or_default();
        *balance += 1;
        if *balance == 0 {
            member.balance.remove(&usage);
        }
        if let Some(turn) = self.turn {
            self.native_turns.insert(turn);
        }
        Ok(())
    }

    /// The replay's counting version (§k.3), decided by the accumulator on
    /// the session's first owned record, which precedes every admission and
    /// member end; until then the value given at construction stands.
    pub(super) fn decide_v2(&mut self, v2: bool) {
        self.v2 = v2;
    }

    /// S10: the parser admitted UI usage from this record. `from_last` is
    /// false when it used a cumulative delta; `identity` is the parser's own
    /// usage event identity and `turn` its running turn id.
    pub(super) fn admitted_usage(
        &mut self,
        value: &Value,
        from_last: bool,
        identity: Option<&str>,
        turn: Option<&str>,
    ) {
        if self.refusal.is_some() {
            return;
        }
        if let Err(reason) = self.admit(value, from_last, identity, turn) {
            self.refuse(reason);
        }
    }

    fn admit(
        &mut self,
        value: &Value,
        from_last: bool,
        identity: Option<&str>,
        turn: Option<&str>,
    ) -> std::result::Result<(), JoinRefusal> {
        self.member.admissions += 1;
        if !from_last {
            return Err(JoinRefusal::CumulativeOnly);
        }
        let identity = identity.ok_or(JoinRefusal::UiShape)?;
        if !self.ui.insert(compact(b"u:", identity)) {
            return Err(JoinRefusal::Overlap);
        }
        let tokens = codex_last_usage_root(value)
            .and_then(Tokens::read)
            .ok_or(JoinRefusal::UiShape)?;
        if self.v2 {
            // §k.3 interim: admissions are not money under V2. Only turn
            // binding is recorded; the group is held at its end otherwise.
            match turn {
                Some(turn) => {
                    self.ui_turns.insert(compact(b"t:", turn));
                }
                None => self.unbound_ui = true,
            }
            return Ok(());
        }
        let member = &mut self.member;
        let balance = member.balance.entry(tokens).or_default();
        *balance -= 1;
        if *balance == 0 {
            member.balance.remove(&tokens);
        }
        if member.last_admitted == Some(tokens) && !member.native_since_admit {
            *member.repeat.entry(tokens).or_default() += 1;
        }
        member.last_admitted = Some(tokens);
        member.native_since_admit = false;
        Ok(())
    }

    /// Member EOF at physical offset `end`: duplicate-origin stubs must be
    /// neutral, and every UI admission must be backed by a native of the
    /// same tuple in the same member (Legacy).
    pub(super) fn end_member(&mut self, end: u64) {
        if self.refusal.is_some() {
            return;
        }
        let member = std::mem::take(&mut self.member);
        let stub = self.plans.get(self.position).is_some_and(|plan| plan.stub);
        if stub && (member.usage_shaped || member.natives > 0 || member.admissions > 0) {
            self.refuse(JoinRefusal::OrdinalRestart);
            return;
        }
        if !self.v2 && member.balance.values().any(|balance| *balance < 0) {
            let reason = if member.natives == 0 {
                JoinRefusal::UiOnlyMember
            } else if member
                .balance
                .iter()
                .filter(|(_, balance)| **balance < 0)
                .all(|(tokens, balance)| {
                    balance.unsigned_abs() <= member.repeat.get(tokens).copied().unwrap_or(0)
                })
            {
                JoinRefusal::UiRepeatUnproven
            } else {
                JoinRefusal::UiUnmatched
            };
            self.refuse(reason);
            return;
        }
        if let Some(after) = member.last_after {
            self.chain = after;
        }
        self.seen.push(MemberSeen {
            last: member.last_ordinal,
            end,
            starts: member.starts,
        });
    }

    /// After the last member: the §k.3 interim V2 hold.
    pub(super) fn finish_group(&mut self) {
        if self.refusal.is_some() || !self.v2 {
            return;
        }
        if self.unbound_ui {
            self.refuse(JoinRefusal::V2UnboundUi);
        } else if !self.ui_turns.is_subset(&self.native_turns) {
            self.refuse(JoinRefusal::V2UiOnlyTurn);
        }
    }
}

/// A member's line 0, read through the parent's `read_header_bytes`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct MemberHeader {
    digest: String,
    size: u64,
    created: Option<i128>,
    ordinal: Option<u64>,
    /// `history_base`: `(thread_id, end_ordinal_exclusive, end_byte_offset)`.
    history_base: Option<(Option<String>, Option<u64>, Option<u64>)>,
    forked: bool,
    subagent_start: bool,
    created_thread: bool,
    classification: (Option<String>, Option<String>),
    /// Identities the member's rollout file name carries.
    names: Vec<String>,
}
crate::heap_layout_bound::fields!(MemberHeader; digest, size, created, ordinal, history_base,
    forked, subagent_start, created_thread, classification, names);

impl MemberHeader {
    pub(super) fn parse(bytes: &[u8], member: &CandidateFile) -> Option<Self> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let meta = codex_session_meta_payload(&value)?;
        let created = string_at(meta, &["timestamp"])
            .or_else(|| string_at(&value, &["timestamp"]))
            .as_deref()
            .and_then(rfc3339_unix_nanos);
        let history_base = meta
            .get("history_base")
            .filter(|base| !base.is_null())
            .map(|base| {
                (
                    resolve_codex_identity_option(codex_identity_at(base, &["thread_id"])),
                    u64_at(base, &["end_ordinal_exclusive"]),
                    u64_at(base, &["end_byte_offset"]),
                )
            });
        Some(Self {
            digest: format!("{:x}", Sha256::digest(bytes)),
            size: member.size_bytes,
            created,
            ordinal: u64_at(&value, &["ordinal"]),
            history_base,
            forked: meta
                .get("forked_from_id")
                .is_some_and(|value| !value.is_null()),
            subagent_start: meta
                .get("subagent_history_start_ordinal")
                .is_some_and(|value| !value.is_null()),
            created_thread: string_eq_at(meta, &["thread_source"], "agent_created_thread"),
            classification: (
                string_at(meta, &["thread_source"]),
                meta.get("source").map(Value::to_string),
            ),
            names: codex_session_id_candidates_from_path(&member.path)
                .iter()
                .map(|name| resolve_codex_identity(name))
                .collect(),
        })
    }

    pub(super) fn digest(&self) -> &str {
        &self.digest
    }

    pub(super) fn ordinal(&self) -> bool {
        self.ordinal.is_some()
    }
}

/// Canonical order and per-position plans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GroupPlan {
    /// Member indices in canonical (replay) order.
    pub(super) order: Vec<usize>,
    pub(super) plans: Vec<MemberPlan>,
    pub(super) ordinal: bool,
}
crate::heap_layout_bound::fields!(GroupPlan; order, plans, ordinal);

/// §a.3 from headers alone. `keys` are the members' local index keys (the
/// chronological tiebreak). Non-ordinal groups still need `order_by_probes`.
pub(super) fn plan_group(
    headers: &[MemberHeader],
    keys: &[String],
) -> std::result::Result<GroupPlan, JoinRefusal> {
    let n = headers.len();
    // Two members with equal line-0 bytes (digest) and equal size are one
    // copied candidate; one set lookup per member (O(n)).
    let mut seen = std::collections::HashSet::with_capacity(n);
    if !headers
        .iter()
        .all(|header| seen.insert((header.digest.as_str(), header.size)))
    {
        return Err(JoinRefusal::CandidateCopy);
    }
    let ordinal = headers.first().is_some_and(MemberHeader::ordinal);
    if headers.iter().any(|header| header.ordinal() != ordinal) {
        return Err(JoinRefusal::MixedOrdinal);
    }
    if headers.iter().any(|header| header.created_thread) {
        return Err(JoinRefusal::CreatedThreadGroup);
    }
    let mut order = (0..n).collect::<Vec<_>>();
    order.sort_by(|a, b| (headers[*a].created, &keys[*a]).cmp(&(headers[*b].created, &keys[*b])));
    let Some(first) = order.first().map(|first| &headers[*first]) else {
        return Err(JoinRefusal::Corrupt);
    };
    if first.forked || first.subagent_start {
        return Err(JoinRefusal::ForkedFromOtherSession);
    }
    if let Some((thread, _, _)) = &first.history_base {
        let named = thread.as_ref().map(|thread| {
            headers
                .iter()
                .any(|header| header.names.iter().any(|name| name == thread))
        });
        return Err(match named {
            // The predecessor is outside the inventory (R1-M3).
            Some(false) => JoinRefusal::MissingPredecessor,
            Some(true) | None => JoinRefusal::HistoryBase,
        });
    }
    let mut plans = vec![MemberPlan::default(); n];
    if !ordinal {
        if headers
            .iter()
            .any(|header| header.forked || header.subagent_start || header.history_base.is_some())
        {
            return Err(JoinRefusal::HistoryBase);
        }
        return Ok(GroupPlan {
            order,
            plans,
            ordinal,
        });
    }
    let mut position = vec![0; n];
    for (at, member) in order.iter().enumerate() {
        position[*member] = at;
    }
    let origins = order
        .iter()
        .copied()
        .filter(|member| headers[*member].history_base.is_none())
        .collect::<Vec<_>>();
    let main = *origins.last().expect("the first member is an origin");
    for origin in &origins {
        let header = &headers[*origin];
        if header.ordinal != Some(0)
            || header.forked
            || header.subagent_start
            || header.classification != headers[main].classification
        {
            return Err(JoinRefusal::OrdinalRestart);
        }
        plans[position[*origin]].stub = *origin != main;
    }
    for (at, member) in order.iter().enumerate() {
        let header = &headers[*member];
        plans[at].first = header.ordinal;
        let Some(base) = &header.history_base else {
            continue;
        };
        if header.forked || header.subagent_start {
            return Err(JoinRefusal::HistoryBase);
        }
        let (Some(thread), Some(end), Some(offset)) = base else {
            return Err(JoinRefusal::HistoryBase);
        };
        let mut named = (0..n).filter(|other| {
            *other != *member && headers[*other].names.iter().any(|name| name == thread)
        });
        let predecessor = match (named.next(), named.next()) {
            (Some(predecessor), None) => predecessor,
            (None, _) => return Err(JoinRefusal::MissingPredecessor),
            (Some(_), Some(_)) => return Err(JoinRefusal::AmbiguousPredecessor),
        };
        // Topological, and the continuation starts exactly at its base.
        if header.ordinal != Some(*end) || position[predecessor] >= at {
            return Err(JoinRefusal::HistoryBase);
        }
        plans[at].binding = Some((position[predecessor], *end, *offset));
        plans[position[predecessor]].watch.push(*end);
    }
    Ok(GroupPlan {
        order,
        plans,
        ordinal,
    })
}

/// v2 probe order for non-ordinal groups: members without a native record
/// first (chronologically), then by the first native's `before`. An equal
/// `before` is `EqualBeforeTie` (no pre-read).
pub(super) fn order_by_probes(
    chronological: &[usize],
    probes: &[Option<Tokens>],
) -> std::result::Result<Vec<usize>, JoinRefusal> {
    let mut order = chronological
        .iter()
        .copied()
        .filter(|member| probes[*member].is_none())
        .collect::<Vec<_>>();
    let mut usage = chronological
        .iter()
        .copied()
        .filter(|member| probes[*member].is_some())
        .collect::<Vec<_>>();
    usage.sort_by_key(|member| probes[*member]);
    if usage
        .windows(2)
        .any(|pair| probes[pair[0]] == probes[pair[1]])
    {
        return Err(JoinRefusal::EqualBeforeTie);
    }
    order.extend(usage);
    Ok(order)
}

/// The first native's `before` of one probed record, if it is one.
pub(super) fn probe_before(value: &Value) -> Option<Tokens> {
    if !string_eq_at(value, &["type"], "token_usage_record") {
        return None;
    }
    let payload = value.get("payload")?;
    let usage = Tokens::read(payload.get("usage")?)?;
    Tokens::read(payload.get("thread_token_usage")?)?.before(usage)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Tokens([u64; 6]);
impl Tokens {
    fn read(value: &Value) -> Option<Self> {
        Some(Self([
            value.get("input_tokens")?.as_u64()?,
            value.get("cached_input_tokens")?.as_u64()?,
            value
                .get("cache_write_input_tokens")
                .map_or(Some(0), Value::as_u64)?,
            value.get("output_tokens")?.as_u64()?,
            value.get("reasoning_output_tokens")?.as_u64()?,
            value.get("total_tokens")?.as_u64()?,
        ]))
    }
    fn before(self, delta: Self) -> Option<Self> {
        let mut values = [0; 6];
        for (i, value) in values.iter_mut().enumerate() {
            *value = self.0[i].checked_sub(delta.0[i])?;
        }
        Some(Self(values))
    }
    /// Componentwise `self >= other`.
    fn covers(self, other: Self) -> bool {
        self.0.iter().zip(other.0).all(|(a, b)| *a >= b)
    }
}

#[derive(Clone)]
struct ContentDigest(Sha256);
impl Default for ContentDigest {
    fn default() -> Self {
        Self(Sha256::new())
    }
}
impl std::io::Write for ContentDigest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ContentDigest {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for Tokens {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    thread_local! {
        static HEADER_READ_PROBE: std::cell::RefCell<Option<BTreeMap<PathBuf, usize>>> = const {
            std::cell::RefCell::new(None)
        };
    }
    pub(in crate::snapshots) fn header_read_started(path: &Path) {
        HEADER_READ_PROBE.with(|probe| {
            if let Some(reads) = probe.borrow_mut().as_mut() {
                *reads.entry(path.to_owned()).or_default() += 1;
            }
        });
    }
    /// Opt-in instrumentation at the real header I/O entry, including retries.
    pub(in crate::snapshots) fn header_reads<T>(
        run: impl FnOnce() -> T,
    ) -> (T, BTreeMap<PathBuf, usize>) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                HEADER_READ_PROBE.with(|probe| *probe.borrow_mut() = None);
            }
        }
        HEADER_READ_PROBE.with(|probe| {
            assert!(probe.borrow().is_none());
            *probe.borrow_mut() = Some(BTreeMap::new());
        });
        let _reset = Reset;
        let result = run();
        let reads = HEADER_READ_PROBE.with(|probe| probe.borrow_mut().take().unwrap());
        (result, reads)
    }
    pub(in crate::snapshots) fn count_header_reads<T>(
        path: &Path,
        run: impl FnOnce() -> T,
    ) -> (T, usize) {
        let (result, reads) = header_reads(run);
        (result, reads.get(path).copied().unwrap_or_default())
    }

    pub(crate) fn usage(input: u64) -> Value {
        json!({"input_tokens":input,"cached_input_tokens":0,"cache_write_input_tokens":0,
            "output_tokens":0,"reasoning_output_tokens":0,"total_tokens":input})
    }
    pub(crate) fn member(owner: &str, response: &str, input: u64, cumulative: u64) -> Vec<Value> {
        // Header time follows the counter: equal header bytes and size would
        // be one copied candidate (`CandidateCopy`).
        let created = format!(
            "2026-10-01T10:{:02}:00Z",
            cumulative.saturating_sub(input) / 100
        );
        vec![
            json!({"type":"session_meta","timestamp":created,"payload":{"id":owner}}),
            json!({"type":"token_usage_record","timestamp":"2026-10-01T10:01:00Z","payload":{
                "thread_id":owner,"response_id":response,"usage":usage(input),"thread_token_usage":usage(cumulative)}}),
            json!({"type":"event_msg","timestamp":format!("2026-10-01T10:{:02}:01Z",cumulative / 100),
                "payload":{"type":"token_count","info":{"last_token_usage":usage(input),"total_token_usage":usage(cumulative)}}}),
        ]
    }
    /// Boot and replay one group in page (no cursor) to its last EOF.
    pub(crate) fn replay_group(
        group: Group,
        traces: Option<Arc<CodexTurnTraceMap>>,
        index: &ScanIndex,
    ) -> std::result::Result<Box<OwnedActiveFile>, GroupEnd> {
        let mut boot = GroupBoot::new(group, index);
        loop {
            match boot.step(None, index) {
                Boot::Pending => {}
                Boot::Ready => break,
                Boot::Refused(reason) => {
                    return Err(GroupEnd::Refused {
                        reason,
                        position: 0,
                        offset: 0,
                        at_eof: false,
                    })
                }
                Boot::Strict | Boot::Unchanged => return Err(GroupEnd::Strict),
            }
        }
        let metadata = CodexTitleMetadata::default();
        let mut job = boot.into_job(JobInputs {
            metadata: &metadata,
            traces,
            ledgers: None,
            artifacts: false,
            context_curve: false,
            index,
        })?;
        let no_scope = |_: &CandidateFile| None;
        let inputs = StepInputs {
            metadata: &metadata,
            attribution: None,
            artifacts: false,
            context_curve: false,
            live_scope: &no_scope,
        };
        for _ in 0..10_000 {
            match step_group(&mut job, &inputs) {
                GroupStep::Read(Ok(true)) => return Ok(job),
                GroupStep::Read(Ok(false)) => {}
                GroupStep::Read(Err(_)) => return Err(GroupEnd::Strict),
                GroupStep::End(end) => return Err(end),
            }
        }
        panic!("bounded group replay did not finish");
    }
    pub(crate) fn fixture() -> (PathBuf, HeaderInventory) {
        // Not keyed on the clock: macOS reads it in whole microseconds, so two
        // tests could share (and one remove) the other's root.
        let root = crate::test_scratch::unique_path("ottto-codex-join");
        let sessions = root.join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let mut paths = BTreeSet::new();
        for (name, rows) in [
            ("a", member(owner, "r-a", 100, 100)),
            ("b", member(owner, "r-b", 200, 300)),
        ] {
            let path = sessions.join(format!("{name}.jsonl"));
            let body = rows
                .iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>();
            fs::write(&path, body).unwrap();
            paths.insert(local_index_key(&path));
        }
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
        while !inventory.step(&CodexTitleMetadata::default()) {}
        (root, inventory)
    }
    #[test]
    fn header_inventory_completes_valid_large_headers_within_population_bound() {
        let (root, _) = fixture();
        let sessions = root.join("sessions");
        let mut paths = BTreeSet::new();
        // Native owning headers carry instructions as well as identity. A
        // supported population of individually bounded headers can therefore
        // exceed 32MiB before any transcript records have been parsed.
        for number in 0..720 {
            let path = sessions.join(format!("large-{number:04}.jsonl"));
            let owner = format!("{number:08x}-1111-4111-8111-ffffffffffff");
            let header = json!({"type":"session_meta","payload":{
                "id":owner,"instructions":"x".repeat(48 * 1024)
            }});
            fs::write(&path, format!("{header}\n")).unwrap();
            paths.insert(local_index_key(&path));
        }
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let metadata = CodexTitleMetadata::default();
        let start = std::time::Instant::now();
        let ((inventory, steps), allocations) = crate::retry_allocation_probe::measure(|| {
            let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
            let mut steps = 0;
            while !inventory.step(&metadata) {
                steps += 1;
            }
            (inventory, steps)
        });
        let complete = inventory.complete;
        let header_count = inventory.headers.len();
        let read_bytes = inventory.read_bytes;
        fs::remove_dir_all(root).unwrap();
        assert!(complete, "valid headers must not turn the whole census red");
        assert_eq!(header_count, paths.len());
        assert_eq!(steps, paths.len(), "one bounded header per native step");
        assert!(read_bytes > 32 * 1024 * 1024);
        assert!(read_bytes <= paths.len() * (MAX_HEADER_BYTES + 1));
        eprintln!(
            "CODEX_HEADER_CENSUS_MEASUREMENT {}",
            json!({"synthetic_headers":header_count,"native_steps":steps,
                "header_read_bytes":read_bytes,"wall_microseconds":start.elapsed().as_micros(),
                "requested_allocation_peak":allocations.requested_peak,
                "usable_allocation_peak":allocations.usable_peak,
                "retained_requested_bytes":allocations.requested_live,
                "retained_usable_bytes":allocations.usable_live})
        );
    }

    #[test]
    fn header_inventory_keeps_individual_header_and_population_refusals() {
        let (root, _) = fixture();
        let sessions = root.join("sessions");
        let path = sessions.join("large.jsonl");
        let mut directories = DirectoryCensus::new();
        for header in [
            format!("{}\n", "x".repeat(MAX_HEADER_BYTES + 1)),
            "{malformed}\n".to_owned(),
            "{\"type\":\"session_meta\",\"payload\":{}}\n".to_owned(),
        ] {
            fs::write(&path, header).unwrap();
            directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
            let mut inventory = HeaderInventory::new(
                std::slice::from_ref(&sessions),
                &BTreeSet::from([local_index_key(&path)]),
                Some(&directories),
            );
            while !inventory.step(&CodexTitleMetadata::default()) {}
            assert!(!inventory.complete);
            assert!(inventory.headers.is_empty());
            assert_eq!(inventory.read_bytes, MAX_HEADER_BYTES + 1);
        }
        let paths = (0..=MAX_HEADER_FILES)
            .map(|number| local_index_key(&sessions.join(format!("{number}.jsonl"))))
            .collect();
        let inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
        assert!(!inventory.complete, "oversized populations remain refused");
        assert_eq!(inventory.pending.len(), MAX_HEADER_FILES + 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn header_owner_lookup_uses_complete_path_order() {
        let (root, inventory) = fixture();
        let template = inventory.headers[0].clone();
        let sessions = root.join("sessions");
        fs::create_dir_all(sessions.join("a")).unwrap();
        let mut paths = BTreeSet::new();
        for (name, owner) in [
            ("a.jsonl", "11111111-2222-4333-8444-555555555555"),
            ("a/b.jsonl", "22222222-2222-4333-8444-555555555555"),
            ("b.jsonl", "33333333-2222-4333-8444-555555555555"),
        ] {
            let path = sessions.join(name);
            fs::write(
                &path,
                format!(
                    "{}\n",
                    json!({"type":"session_meta","payload":{"id":owner}})
                ),
            )
            .unwrap();
            paths.insert(local_index_key(&path));
        }
        let mut actual = HeaderInventory::new(&[sessions], &paths, Some(&inventory.directories));
        while !actual.step(&CodexTitleMetadata::default()) {}
        assert_eq!(actual.headers.len(), 3);
        for header in &actual.headers {
            assert_eq!(
                actual.owner_for_path(&header.candidate.path),
                Some(header.owner.as_str())
            );
        }
        assert!(actual
            .owner_for_path(&root.join("sessions/missing.jsonl"))
            .is_none());
        assert_eq!(
            inventory.owner_for_path(&template.candidate.path),
            Some(template.owner.as_str())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn header_inventory_detects_late_members_and_owner_changes() {
        let (root, inventory) = fixture();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        inventory.validate_membership(owner, &root).unwrap();
        fs::write(root.join("sessions/new.jsonl"), "new member").unwrap();
        assert!(inventory.validate_membership(owner, &root).is_err());
        fs::remove_dir_all(root).unwrap();
        let (root, inventory) = fixture();
        let rows = member("ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        assert!(inventory.validate_membership(owner, &root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn group_replay_uses_native_parser_and_revalidates_both_passes() {
        let (root, inventory) = fixture();
        let group = inventory.groups().into_values().next().unwrap();
        let job = replay_group(group, None, &ScanIndex::default()).unwrap();
        let OwnedActiveFile {
            parser,
            candidate: last,
            aliases: members,
            ..
        } = *job;
        assert_eq!(members.len(), 2);
        let parsed = parser
            .finish(
                &last.opened_object_identity,
                &last.path,
                "2026-10-01T12:00:00Z",
                last.source_file_fingerprint,
                Some(&CodexTitleMetadata::default()),
                None,
                None,
            )
            .unwrap();
        assert!(parsed.complete());
        assert_eq!(parsed.snapshots.len(), 1);
        assert_eq!(parsed.snapshots[0].input_tokens, 300);
        assert_eq!(parsed.report.parsed_json_line_count, 6);
        fs::remove_dir_all(root).unwrap();
    }
    pub(crate) fn native_join_fixture_root(priority: bool) -> PathBuf {
        let root = fixture().0;
        if priority {
            let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
            let mut rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
            rows.insert(
                1,
                json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
            );
            fs::write(
                root.join("sessions/b.jsonl"),
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            let connection = Connection::open(root.join("logs_2.sqlite")).unwrap();
            connection.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, ts INTEGER, feedback_log_body TEXT)", []).unwrap();
            connection.execute("INSERT INTO logs (ts, feedback_log_body) VALUES (?1, ?2)", rusqlite::params![
                unix_seconds(SystemTime::now()).unwrap() as i64,
                format!("turn{{turn.id={turn}}}: websocket request: {{\"type\":\"response.create\",\"service_tier\":\"priority\",\"model\":\"gpt-5.2\"}}")
            ]).unwrap();
        }
        root
    }
    pub(crate) fn scan(
        root: &Path,
        index: ScanIndex,
        limit: usize,
    ) -> (ScanIndex, SourceScanResult) {
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            index,
            "2026-10-06T23:00:00Z",
            7,
            limit,
            false,
            None,
            &[],
            false,
            false,
        );
        for _ in 0..1000 {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("bounded native scan did not finish");
    }
    #[test]
    fn production_scanner_aliases_need_common_settlement_and_skip_on_restart() {
        let (root, _) = fixture();
        let previous = ScanIndex::default();
        let (mut index, mut result) = scan(&root, previous.clone(), 2);
        assert_eq!(result.scanned_file_count, 2);
        assert_eq!(result.snapshots.len(), 2, "one alias per physical member");
        assert!(result.snapshots.iter().all(|item| item.input_tokens == 300));
        assert!(result.census_complete, "{result:?}");
        result
            .codex_joining_validator()
            .unwrap()
            .validate(&result.snapshots)
            .unwrap();
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            accepted.len(),
            1,
            "physical aliases share one body identity"
        );
        assert_eq!(
            index
                .committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new())
                .files
                .len(),
            0,
            "lost ACK cannot settle either new physical member"
        );
        let mut settled = index.committable_subset(&previous, &accepted, &BTreeMap::new());
        assert_eq!(settled.files.len(), 2);
        let path = root.join("index.json");
        settled.save(&path).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        let (_index, restarted) = scan(&root, loaded, 2);
        assert!(
            restarted.snapshots.is_empty(),
            "an acknowledged group needs no new upload"
        );
        assert_eq!(restarted.semantic_noop_count, 2);
        fs::remove_dir_all(root).unwrap();
    }
    /// The two-member fixture with creation times, so a cutover can select V2.
    /// Each member's native and UI share one bound turn (#630: a V2 group
    /// proves native-turn UI, §k.3 rule 2).
    pub(crate) fn counting_v2_fixture() -> (PathBuf, [String; 2]) {
        counting_v2_fixture_with(true)
    }
    /// #603's original rows: UI in an unbound span, which a V2 group holds
    /// (§k.3 rule 5).
    pub(crate) fn counting_v2_unbound_fixture() -> (PathBuf, [String; 2]) {
        counting_v2_fixture_with(false)
    }
    fn counting_v2_fixture_with(bound: bool) -> (PathBuf, [String; 2]) {
        let (root, _) = fixture();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        for (name, mut rows) in [
            ("a", member(owner, "r-a", 100, 100)),
            ("b", member(owner, "r-b", 200, 300)),
        ] {
            if bound {
                let turn = format!("turn-{name}");
                // The native names its turn (`payload.turn_id`), as Codex
                // writes it; the UI follows inside the same open turn.
                rows[1]["payload"]["turn_id"] = json!(turn);
                let at = rows[0]["timestamp"].clone();
                rows.insert(
                    1,
                    json!({"type":"event_msg","timestamp":at,
                        "payload":{"type":"task_started","turn_id":turn}}),
                );
                let at = rows[rows.len() - 1]["timestamp"].clone();
                rows.push(json!({"type":"event_msg","timestamp":at,
                    "payload":{"type":"task_complete","turn_id":turn}}));
            }
            let body = rows
                .into_iter()
                .map(|mut row| {
                    if row["type"] == "session_meta" {
                        row["payload"]["timestamp"] = json!("2026-10-01T10:00:00Z");
                    }
                    serde_json::to_string(&row).unwrap() + "\n"
                })
                .collect::<String>();
            fs::write(root.join("sessions").join(format!("{name}.jsonl")), body).unwrap();
        }
        let keys = ["a", "b"]
            .map(|name| local_index_key(&root.join("sessions").join(format!("{name}.jsonl"))));
        (root, keys)
    }
    /// The selected local ACK facts the counting mark must move with.
    fn local_ack(
        entry: &ScanIndexEntry,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        (
            entry.last_snapshot_fingerprint.clone(),
            entry.last_upload_body_witness.clone(),
            entry.codex_joined_member_set.clone(),
            entry.codex_protected_owner.clone(),
        )
    }
    /// Finalizes one scan, saves its selected index over `file` (compare-and-
    /// swap against the generation it was loaded at) and reloads it.
    fn save_selected(
        root: &Path,
        file: &str,
        mut working: ScanIndex,
        mut result: SourceScanResult,
        previous: &ScanIndex,
        hold_owner: Option<&str>,
    ) -> ScanIndex {
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        if let Some(owner) = hold_owner {
            result.hold_codex_groups(
                &mut working,
                previous,
                &BTreeSet::from([resolve_codex_identity(owner)]),
                "synthetic counting hold",
            );
        }
        result.finish_codex_capture_boundary(&mut working);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let path = root.join(file);
        working
            .committable_subset(previous, &accepted, &BTreeMap::new())
            .save(&path)
            .unwrap();
        ScanIndex::load(&path).unwrap()
    }
    #[test]
    fn counting_v2_group_is_configured_once_and_folded_once() {
        let (root, keys) = counting_v2_fixture();
        let (legacy_index, legacy) = scan(&root, ScanIndex::default(), 2);
        let _cutover = codex_counting_version::TestCutover::set(0);
        let (index, counted) = scan(&root, ScanIndex::default(), 2);
        assert_eq!(counted.snapshots.len(), 2, "one alias per physical member");
        let receipts = counted
            .codex_counting_v2
            .as_deref()
            .expect("an executed configured group parse owns receipts");
        assert_eq!(receipts.v2_sessions, 1, "a joined group folds once");
        // One carried accumulator saw both members' records, each inside
        // its member's bound turn (#630 re-fixture: was 2 and 2 unbound).
        assert_eq!(receipts.native_counted, 2, "both members' natives");
        assert_eq!(receipts.native_outside_open_turn, 0);
        assert_eq!(receipts.ui_in_unbound_span, 0);
        for key in &keys {
            assert!(index.files[key].codex_counting_v2, "V2 marks every member");
            assert!(!legacy_index.files[key].codex_counting_v2);
        }
        assert!(
            legacy.codex_counting_v2.is_none(),
            "an inactive scan reports no receipts, not a zero block"
        );
        for (counted, legacy) in counted.snapshots.iter().zip(&legacy.snapshots) {
            assert_eq!(counted.input_tokens, legacy.input_tokens);
            assert_eq!(counted.input_tokens, 300);
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn counting_v2_member_mark_moves_only_with_the_selected_saved_ack() {
        let (root, keys) = counting_v2_fixture();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let previous = {
            let _cutover = codex_counting_version::TestCutover::set(0);
            let (index, result) = scan(&root, ScanIndex::default(), 2);
            save_selected(&root, "v2.json", index, result, &ScanIndex::default(), None)
        };
        for key in &keys {
            assert!(previous.files[key].codex_counting_v2, "saved V2 ACK");
            assert!(previous.files[key].last_snapshot_fingerprint.is_some());
        }
        // The held and settled outcomes are alternatives: each starts from its
        // own copy of the saved index the cycle loaded.
        for file in ["held.json", "settled.json"] {
            fs::copy(root.join("v2.json"), root.join(file)).unwrap();
        }
        // New content, parsed by an inactive build: a Legacy group decision.
        let path = root.join("sessions/b.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        for row in member(owner, "r-c", 200, 500).into_iter().skip(1) {
            text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
        }
        fs::write(&path, text).unwrap();
        let legacy_scan = || {
            let (working, result) = scan(&root, previous.clone(), 2);
            for key in &keys {
                assert!(!working.files[key].codex_counting_v2);
            }
            (working, result)
        };
        // A held group restores the old mark with the old ACK in saved state.
        let (working, result) = legacy_scan();
        let held = save_selected(&root, "held.json", working, result, &previous, Some(owner));
        for key in &keys {
            assert!(held.files[key].codex_counting_v2, "mark kept with its ACK");
            assert_eq!(local_ack(&held.files[key]), local_ack(&previous.files[key]));
        }
        // Paired control: the selected save records false with the new facts.
        let (working, result) = legacy_scan();
        let settled = save_selected(&root, "settled.json", working, result, &previous, None);
        for key in &keys {
            assert!(!settled.files[key].codex_counting_v2, "false with new ACK");
            assert_ne!(
                settled.files[key].last_snapshot_fingerprint,
                previous.files[key].last_snapshot_fingerprint
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn applied_priority_survives_trace_expiry_without_pricing_appended_same_turn() {
        let (root, inventory) = fixture();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let mut rows = member(owner, "r-b", 200, 300);
        rows.insert(
            1,
            json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
        );
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let mut traces = CodexTurnTraceMap::default();
        traces.priority_turns.insert(turn.into());
        let job = replay_group(
            inventory.groups().into_values().next().unwrap(),
            Some(Arc::new(traces.clone())),
            &ScanIndex::default(),
        )
        .unwrap();
        let OwnedActiveFile {
            aliases: members,
            applied_receipts: receipts,
            ..
        } = *job;
        let mut index = ScanIndex::default();
        for member in members {
            let key = local_index_key(&member.path);
            index.record(member, None, ScanParseOutcome::Snapshot);
            let entry = index.files.get_mut(&key).unwrap();
            entry.codex_applied_tier_receipt = receipts[&key].clone();
            entry.codex_applied_tier_receipt_required = entry.codex_applied_tier_receipt.is_some();
        }
        let appended = member(owner, "r-c", 200, 500);
        rows.extend(appended.into_iter().skip(1));
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let (_, fresh) = {
            // Reuse the real roots and make a fresh header census after append.
            let paths = inventory
                .headers
                .iter()
                .map(|header| local_index_key(&header.candidate.path))
                .collect();
            let mut directories = DirectoryCensus::new();
            let sessions = root.join("sessions");
            directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
            let mut fresh = HeaderInventory::new(&[sessions], &paths, Some(&directories));
            while !fresh.step(&CodexTitleMetadata::default()) {}
            ((), fresh)
        };
        let job = replay_group(fresh.groups().into_values().next().unwrap(), None, &index).unwrap();
        let OwnedActiveFile {
            parser,
            candidate: last,
            applied_receipts: receipts,
            ..
        } = *job;
        let parsed = parser
            .finish(
                &last.opened_object_identity,
                &last.path,
                "2026-10-06T23:00:00Z",
                last.source_file_fingerprint,
                Some(&CodexTitleMetadata::default()),
                None,
                None,
            )
            .unwrap();
        assert!(parsed.complete());
        let item = &parsed.snapshots[0];
        assert_eq!(item.input_tokens, 500);
        let priority = item
            .model_usage
            .iter()
            .filter(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("priority")
            })
            .map(|row| row.input_tokens)
            .sum::<u64>();
        assert_eq!(
            priority, 200,
            "only the previously applied physical contribution stays priority"
        );
        assert_eq!(
            receipts[&local_index_key(&root.join("sessions/b.jsonl"))]
                .as_ref()
                .unwrap()
                .tiers
                .len(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn singleton_headers_across_distinct_homes_cannot_overwrite_one_owner() {
        let (root, _) = fixture();
        let other = root.join("other-home/sessions");
        fs::create_dir_all(&other).unwrap();
        fs::rename(root.join("sessions/b.jsonl"), other.join("b.jsonl")).unwrap();
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions"), other],
            ScanIndex::default(),
            "2026-10-06T23:00:00Z",
            7,
            2,
            false,
            None,
            &[],
            false,
            false,
        );
        loop {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => {
                    assert!(scan.snapshots.is_empty());
                    assert_eq!(scan.ownership_incomplete_file_count, 2);
                    assert!(index.files.is_empty());
                    break;
                }
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn incomplete_native_replay_cannot_publish_a_partial_joined_replacement() {
        let (root, _) = fixture();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        let bad = json!({"type":"event_msg","payload":{"type":"token_count","info":{
            "total_token_usage":{"input_tokens":"not-a-number","output_tokens":"not-a-number"}}}});
        assert!(codex_total_usage(&bad).is_none());
        let path = root.join("sessions/b.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str(&(serde_json::to_string(&bad).unwrap() + "\n"));
        fs::write(&path, text).unwrap();
        let (after, held) = scan(&root, previous.clone(), 2);
        assert!(held.snapshots.is_empty());
        assert!(!held.census_complete);
        assert_eq!(held.ownership_incomplete_file_count, 2);
        assert_eq!(
            serde_json::to_value(&after.files).unwrap(),
            serde_json::to_value(&previous.files).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn losing_a_joined_member_cannot_replace_history_with_the_remaining_tail() {
        let (root, _) = fixture();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
        let path = root.join("sessions/b.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        for row in member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 200, 500)
            .into_iter()
            .skip(1)
        {
            text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
        }
        fs::write(path, text).unwrap();
        let (after, held) = scan(&root, previous.clone(), 2);
        assert!(held.snapshots.is_empty());
        assert!(!held.census_complete);
        assert_eq!(
            held.ownership_incomplete_file_count, 2,
            "both the absent member and the remaining tail are held"
        );
        assert_eq!(
            serde_json::to_value(&after.files).unwrap(),
            serde_json::to_value(&previous.files).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn losing_last_of_three_joined_members_holds_contiguous_prefix_and_allows_sibling() {
        let (root, _) = fixture();
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let write = |name: &str, rows: Vec<Value>| {
            fs::write(
                root.join("sessions").join(name),
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        };
        write("c.jsonl", member(owner, "r-c", 100, 400));
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 4);
        assert!(result.snapshots.iter().all(|item| item.input_tokens == 400));
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        fs::remove_file(root.join("sessions/c.jsonl")).unwrap();
        let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
        write("d.jsonl", member(healthy, "healthy", 100, 100));
        let (after, held) = scan(&root, previous.clone(), 4);
        assert!(!held.census_complete);
        assert_eq!(held.ownership_incomplete_file_count, 3);
        assert_eq!(held.snapshots.len(), 1);
        assert_eq!(held.snapshots[0].source_session_id, healthy);
        for (key, entry) in &previous.files {
            assert_eq!(
                serde_json::to_value(&after.files[key]).unwrap(),
                serde_json::to_value(entry).unwrap()
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn contradictory_creator_pairs_hold_joined_body_before_account_fallback() {
        let (root, _) = fixture();
        for (name, creator) in [("a.jsonl", "first"), ("b.jsonl", "second")] {
            let path = root.join("sessions").join(name);
            let mut rows = fs::read_to_string(&path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            rows[0]["payload"]["creator_user_id"] = json!(creator);
            rows[0]["payload"]["creator_account_id"] = json!("synthetic-workspace");
            fs::write(
                path,
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        }
        let (index, held) = scan(&root, ScanIndex::default(), 2);
        assert!(
            held.snapshots.is_empty(),
            "no conflicted item can reach cached or current-home binding"
        );
        assert_eq!(held.ownership_incomplete_file_count, 2);
        assert!(!held.census_complete);
        let causes = serde_json::to_value(
            held.local_codex_diagnostics
                .unwrap()
                .unreadable_causes
                .projection(held.unreadable_path_count as u64),
        )
        .unwrap();
        assert_eq!(
            causes["counts"][5], 1,
            "one alias guard event, not two files"
        );
        assert_eq!(causes["unattributed"], 0);

        assert!(index.files.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn configured_root_symlink_uses_resolved_inventory_roots() {
        let (root, _) = fixture();
        let configured = root.join("configured-sessions");
        std::os::unix::fs::symlink(root.join("sessions"), &configured).unwrap();
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[configured],
            ScanIndex::default(),
            "2026-10-06T23:00:00Z",
            7,
            2,
            false,
            None,
            &[],
            false,
            false,
        );
        loop {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { scan, .. } => {
                    assert!(scan.census_complete, "{scan:?}");
                    assert_eq!(scan.snapshots.len(), 2);
                    assert!(scan.snapshots.iter().all(|item| item.input_tokens == 300));
                    scan.codex_joining_validator()
                        .unwrap()
                        .validate(&scan.snapshots)
                        .unwrap();
                    break;
                }
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn shared_home_validation_checks_roster_once_and_rechecks_ownership_each_boundary() {
        let (root, _) = fixture();
        let first = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let mut owners = BTreeSet::from([first.to_owned()]);
        for i in 1..=3 {
            let owner = format!("{i:08x}-bbbb-4ccc-8ddd-{i:012x}");
            owners.insert(owner.clone());
            for (part, input, after) in [("a", 100, 100), ("b", 200, 300)] {
                let rows = member(&owner, &format!("r-{i}-{part}"), input, after);
                fs::write(
                    root.join("sessions").join(format!("{i}-{part}.jsonl")),
                    rows.iter()
                        .map(|row| serde_json::to_string(row).unwrap() + "\n")
                        .collect::<String>(),
                )
                .unwrap();
            }
        }
        let (_, result) = scan(&root, ScanIndex::default(), 8);
        assert_eq!(result.snapshots.len(), 8);
        let validation = result.codex_join_validation.as_ref().unwrap();
        assert_eq!(validation.groups.len(), 4);
        assert_eq!(
            validation.validate(&owners).unwrap(),
            8,
            "eight roster stats, not eight per group"
        );
        let selected = BTreeSet::from([first.to_owned()]);
        assert_eq!(validation.validate(&selected).unwrap(), 8);
        // A previously unrelated file can enter the selected owner's group
        // without changing directory membership. No boundary result is cached.
        let path = root.join("sessions/1-a.jsonl");
        let mut rows = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        rows[0]["payload"]["id"] = json!(first);
        fs::write(
            path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        assert!(validation.validate(&selected).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn replay_owner_rewrite_after_inventory_cannot_escape_validation() {
        let (root, _) = fixture();
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            ScanIndex::default(),
            "2026-10-06T23:00:00Z",
            7,
            2,
            false,
            None,
            &[],
            false,
            false,
        );
        let changed = "ffffffff-1111-4111-8111-ffffffffffff";
        let mut rewritten = false;
        loop {
            if owned.codex_join_prepared && !owned.codex_join_groups.is_empty() && !rewritten {
                for (name, response, input, after) in [
                    ("a.jsonl", "a-new", 100, 100),
                    ("b.jsonl", "b-new", 200, 300),
                ] {
                    let rows = member(changed, response, input, after);
                    fs::write(
                        root.join("sessions").join(name),
                        rows.iter()
                            .map(|row| serde_json::to_string(row).unwrap() + "\n")
                            .collect::<String>(),
                    )
                    .unwrap();
                }
                rewritten = true;
            }
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => {
                    assert!(rewritten);
                    assert!(scan.snapshots.is_empty());
                    assert_eq!(scan.ownership_incomplete_file_count, 2);
                    assert!(index.files.is_empty());
                    break;
                }
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn protected_files_cannot_be_repurposed_under_a_new_inventoried_owner() {
        let (root, _) = fixture();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        let changed = "ffffffff-1111-4111-8111-ffffffffffff";
        for (name, response, input, after) in [
            ("a.jsonl", "a-new", 100, 100),
            ("b.jsonl", "b-new", 200, 300),
        ] {
            let rows = member(changed, response, input, after);
            fs::write(
                root.join("sessions").join(name),
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        }
        let (after, held) = scan(&root, previous.clone(), 2);
        assert!(held.snapshots.is_empty());
        assert!(!held.census_complete);
        assert_eq!(
            serde_json::to_value(&after.files).unwrap(),
            serde_json::to_value(&previous.files).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn semantic_noop_checkpoint_still_checks_late_member_roster() {
        let (root, _) = fixture();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        let path = root.join("sessions/a.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push('\n');
        fs::write(path, text).unwrap();
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            previous,
            "2026-10-06T23:00:00Z",
            7,
            2,
            false,
            None,
            &[],
            false,
            false,
        );
        let mut added = false;
        loop {
            if !added && owned.codex_join_active.is_some() {
                let rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "late", 100, 400);
                fs::write(
                    root.join("sessions/c.jsonl"),
                    rows.iter()
                        .map(|row| serde_json::to_string(row).unwrap() + "\n")
                        .collect::<String>(),
                )
                .unwrap();
                added = true;
            }
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete {
                    mut index,
                    mut scan,
                    ..
                } => {
                    assert!(added);
                    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                    assert!(scan.snapshots.is_empty());
                    scan.codex_joining_validator()
                        .unwrap()
                        .validate(&scan.snapshots)
                        .unwrap();
                    assert!(
                        scan.validate_codex_checkpoint().is_err(),
                        "no-op suppression cannot make a stale checkpoint eligible"
                    );
                    break;
                }
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn held_group_does_not_poison_known_healthy_owner_on_the_next_page() {
        let (root, _) = fixture();
        let bad = member(
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "bad-overlap",
            200,
            250,
        );
        fs::write(
            root.join("sessions/b.jsonl"),
            bad.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
        let rows = member(healthy, "healthy", 100, 100);
        fs::write(
            root.join("sessions/c.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let (index, first) = scan(&root, ScanIndex::default(), 2);
        assert!(first.snapshots.is_empty());
        assert!(!first.census_complete);
        // Outcome R: the refused owner stays blocked as settleable residue.
        assert!(index
            .codex_state_only_blocked_session_ids
            .contains("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"));
        let (_, next) = scan(&root, index, 2);
        assert_eq!(next.snapshots.len(), 1);
        assert_eq!(next.snapshots[0].source_session_id, healthy);
        fs::remove_dir_all(root).unwrap();
    }
    const RETAINED_AT: &str = "2026-10-06T23:00:00Z";
    const KNOWN: &str = "11111111-1111-4111-8111-111111111111";
    const UNRELATED: &str = "22222222-2222-4222-8222-222222222222";
    fn write_rows(path: &Path, rows: &[Value]) {
        fs::write(
            path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
    fn retained_page(
        root: &Path,
        index: ScanIndex,
        hints: &[PathBuf],
    ) -> (ScanIndex, SourceScanResult) {
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            index,
            RETAINED_AT,
            7,
            10,
            false,
            None,
            hints,
            false,
            false,
        );
        for _ in 0..1000 {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("bounded native scan did not finish");
    }
    /// A settled `known` rollout beside one whose malformed line keeps the
    /// generation red, so it is retained behind its bounded retry deadline.
    fn retained_red_generation(known: Vec<Value>) -> (PathBuf, ScanIndex) {
        let root = crate::test_scratch::unique_path("ottto-codex-retained");
        let sessions = root.join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        write_rows(&sessions.join("a.jsonl"), &known);
        let red = "33333333-3333-4333-8333-333333333333";
        fs::write(
            sessions.join("red.jsonl"),
            serde_json::to_string(&member(red, "r-red", 10, 10)[0]).unwrap() + "\n{not json\n",
        )
        .unwrap();
        let (mut index, mut result) = retained_page(&root, ScanIndex::default(), &[]);
        assert!(!result.census_complete);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let settled = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        let deadline = settled
            .traversal
            .as_ref()
            .and_then(|traversal| traversal.unhealthy_retry_not_before_unix_seconds)
            .expect("red generation keeps a retry deadline");
        assert!(deadline > rfc3339_unix_seconds(RETAINED_AT).unwrap());
        (root, settled)
    }
    fn retry_deadline(index: &ScanIndex) -> Option<u64> {
        index
            .traversal
            .as_ref()
            .and_then(|traversal| traversal.unhealthy_retry_not_before_unix_seconds)
    }
    #[test]
    fn retained_generation_admits_new_rollout_without_holding_known_update() {
        let (root, settled) = retained_red_generation(member(KNOWN, "k-1", 100, 100));
        let deadline = retry_deadline(&settled);
        let known = root.join("sessions/a.jsonl");
        let mut text = fs::read_to_string(&known).unwrap();
        for row in &member(KNOWN, "k-2", 150, 250)[1..] {
            text.push_str(&(serde_json::to_string(row).unwrap() + "\n"));
        }
        fs::write(&known, text).unwrap();
        let new = root.join("sessions/new.jsonl");
        write_rows(&new, &member(UNRELATED, "n-1", 70, 70));
        let (index, page) = retained_page(&root, settled, &[known, new.clone()]);
        let mut totals = page
            .snapshots
            .iter()
            .map(|item| (item.source_session_id.clone(), item.input_tokens))
            .collect::<Vec<_>>();
        totals.sort();
        assert_eq!(
            totals,
            vec![(KNOWN.to_string(), 250), (UNRELATED.to_string(), 70)],
            "a rollout created after the walk must not hold the known update"
        );
        assert_eq!(page.scanned_file_count, 2, "only the changed and new files");
        assert_eq!(retry_deadline(&index), deadline, "no re-walk was forced");
        assert!(index
            .traversal
            .as_ref()
            .unwrap()
            .codex_rollout_paths
            .contains(&local_index_key(&new)));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn retained_generation_discovers_new_rollout_without_a_watcher_hint() {
        let (root, settled) = retained_red_generation(member(KNOWN, "k-1", 100, 100));
        let deadline = retry_deadline(&settled);
        let (idle, quiet) = retained_page(&root, settled, &[]);
        assert_eq!(
            quiet.scanned_file_count, 0,
            "unchanged directories re-list nothing"
        );
        assert!(quiet.snapshots.is_empty());
        write_rows(
            &root.join("sessions/new.jsonl"),
            &member(UNRELATED, "n-1", 70, 70),
        );
        let (index, page) = retained_page(&root, idle, &[]);
        assert_eq!(page.scanned_file_count, 1);
        assert_eq!(page.snapshots.len(), 1);
        assert_eq!(page.snapshots[0].source_session_id, UNRELATED);
        assert_eq!(retry_deadline(&index), deadline);
        let (_, again) = retained_page(&root, index, &[]);
        assert_eq!(
            again.scanned_file_count, 0,
            "an admitted file is not re-read"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn retained_generation_never_sends_a_settled_segment_without_its_new_sibling() {
        // The known owner's second physical segment appears after the walk.
        // Emitting the settled first segment alone would replace the session
        // with part of its usage; it must be joined or held, while an
        // unrelated new rollout on the same page is still admitted.
        let (root, settled) = retained_red_generation(member(KNOWN, "r-a", 100, 100));
        let segment = root.join("sessions/b.jsonl");
        write_rows(&segment, &member(KNOWN, "r-b", 200, 300));
        let new = root.join("sessions/new.jsonl");
        write_rows(&new, &member(UNRELATED, "n-1", 70, 70));
        let (_, page) = retained_page(&root, settled, &[segment, new]);
        let known = page
            .snapshots
            .iter()
            .filter(|item| item.source_session_id == KNOWN)
            .collect::<Vec<_>>();
        assert!(
            known.iter().all(|item| item.input_tokens == 300),
            "a known segment cannot be sent alone once its sibling exists: {known:?}"
        );
        assert!(!known.is_empty() || page.ownership_incomplete_file_count >= 2);
        assert!(page
            .snapshots
            .iter()
            .any(|item| item.source_session_id == UNRELATED && item.input_tokens == 70));
        fs::remove_dir_all(root).unwrap();
    }
    fn inventory_hold(index: &ScanIndex) -> Option<&super::super::CodexInventoryHold> {
        index
            .traversal
            .as_ref()
            .and_then(|traversal| traversal.residue.codex_inventory_hold.as_ref())
    }
    /// A retained red generation where a new unreadable first record and a
    /// valid unrelated rollout arrive together, so the page holds both.
    fn held_behind_unreadable_header() -> (PathBuf, ScanIndex, PathBuf, PathBuf, String) {
        let (root, settled) = retained_red_generation(member(KNOWN, "k-1", 100, 100));
        let unreadable = root.join("sessions/unreadable.jsonl");
        fs::write(&unreadable, "not a header\n").unwrap();
        let new = root.join("sessions/new.jsonl");
        write_rows(&new, &member(UNRELATED, "n-1", 70, 70));
        let (held_index, held) = retained_page(&root, settled, &[unreadable.clone(), new.clone()]);
        assert!(held.snapshots.is_empty(), "{:?}", held.snapshots);
        assert!(held.ownership_incomplete_file_count > 0);
        let (c, [unknown, _, _]) = held.causes.summary(held.ownership_incomplete_file_count);
        assert!(c[ownership::INVENTORY] > 0);
        assert_eq!(
            c[..6].iter().sum::<usize>() + unknown,
            held.ownership_incomplete_file_count
        );
        let hold = inventory_hold(&held_index).expect("the held page is owed a retry");
        assert!(hold.owed.contains(&local_index_key(&new)));
        assert!(hold
            .refused_headers
            .contains_key(&local_index_key(&unreadable)));
        let witness = path_witness(&new).unwrap();
        (root, held_index, unreadable, new, witness)
    }
    #[test]
    fn unreadable_new_header_holds_the_page_only_while_it_is_unreadable() {
        // An unreadable header has no provable owner, so it may belong to any
        // selected session: the page stays held, and an idle tick re-reads
        // nothing. Once it is gone, the valid session held with it is admitted
        // on the next ordinary tick: no write to it, no hint for it, no walk.
        let (root, held_index, unreadable, new, witness) = held_behind_unreadable_header();
        let deadline = retry_deadline(&held_index);
        let (idle_index, idle) = retained_page(&root, held_index, &[]);
        assert_eq!(
            idle.scanned_file_count, 0,
            "unmoved evidence re-reads nothing"
        );
        assert!(idle.snapshots.is_empty());
        assert!(inventory_hold(&idle_index).is_some());
        // The hold is durable state: it survives a service restart.
        let restarted: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&idle_index).unwrap()).unwrap();
        assert_eq!(inventory_hold(&restarted), inventory_hold(&idle_index));
        fs::remove_file(&unreadable).unwrap();
        let (index, page) = retained_page(&root, restarted, &[]);
        assert_eq!(
            page.snapshots
                .iter()
                .map(|item| (item.source_session_id.as_str(), item.input_tokens))
                .collect::<Vec<_>>(),
            vec![(UNRELATED, 70)],
            "the originally held valid session recovers"
        );
        assert_eq!(page.scanned_file_count, 1);
        assert_eq!(
            path_witness(&new).unwrap(),
            witness,
            "the held file was not rewritten"
        );
        assert_eq!(retry_deadline(&index), deadline, "no re-walk was forced");
        assert!(inventory_hold(&index).is_none());
        let (_, again) = retained_page(&root, index, &[]);
        assert_eq!(
            again.scanned_file_count, 0,
            "a recovered file is not re-read"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn header_that_vanished_before_its_read_releases_the_hold_once_unlisted() {
        // The refused record was already gone when the inventory reached it,
        // so its recorded witness is absent and can never change. Leaving the
        // roster is the evidence that releases the held valid session.
        let (root, mut held_index, unreadable, _, _) = held_behind_unreadable_header();
        let key = local_index_key(&unreadable);
        let hold = held_index
            .traversal
            .as_mut()
            .and_then(|traversal| traversal.residue.codex_inventory_hold.as_mut())
            .unwrap();
        *hold.refused_headers.get_mut(&key).unwrap() = None;
        fs::remove_file(&unreadable).unwrap();
        let (index, page) = retained_page(&root, held_index, &[]);
        assert!(!index
            .traversal
            .as_ref()
            .unwrap()
            .codex_rollout_paths
            .contains(&key));
        assert_eq!(
            page.snapshots
                .iter()
                .map(|item| (item.source_session_id.as_str(), item.input_tokens))
                .collect::<Vec<_>>(),
            vec![(UNRELATED, 70)]
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn repaired_header_releases_the_held_page_and_a_still_unreadable_one_does_not() {
        let (root, held_index, unreadable, new, witness) = held_behind_unreadable_header();
        let deadline = retry_deadline(&held_index);
        // The blocker changes but still proves no owner: the owed candidates
        // are tried again once, held again, and nothing is emitted.
        fs::write(&unreadable, "still not a header\n").unwrap();
        let (still_index, still) =
            retained_page(&root, held_index, std::slice::from_ref(&unreadable));
        assert!(still.snapshots.is_empty(), "{:?}", still.snapshots);
        assert!(still.ownership_incomplete_file_count > 0);
        assert!(inventory_hold(&still_index)
            .is_some_and(|hold| hold.owed.contains(&local_index_key(&new))));
        let (idle_index, idle) = retained_page(&root, still_index, &[]);
        assert_eq!(
            idle.scanned_file_count, 0,
            "unmoved evidence re-reads nothing"
        );
        // Repaired in place: same directory, same inode, a provable owner.
        let repaired_owner = "44444444-4444-4444-8444-444444444444";
        write_rows(&unreadable, &member(repaired_owner, "l-1", 30, 30));
        let (index, page) = retained_page(&root, idle_index, &[unreadable]);
        let mut totals = page
            .snapshots
            .iter()
            .map(|item| (item.source_session_id.clone(), item.input_tokens))
            .collect::<Vec<_>>();
        totals.sort();
        assert_eq!(
            totals,
            vec![
                (UNRELATED.to_string(), 70),
                (repaired_owner.to_string(), 30)
            ],
            "the held valid session and the repaired one are both admitted"
        );
        assert_eq!(page.scanned_file_count, 2);
        assert_eq!(
            path_witness(&new).unwrap(),
            witness,
            "the held file was not rewritten"
        );
        assert_eq!(retry_deadline(&index), deadline, "no re-walk was forced");
        assert!(inventory_hold(&index).is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn retired_sources_keep_protected_history_and_quiet_retry_is_idempotent() {
        let root = native_join_fixture_root(true);
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 3);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        result.finish_codex_capture_boundary(&mut working);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous =
            working.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        assert_eq!(previous.files.len(), 2);
        assert!(previous
            .files
            .values()
            .all(|entry| entry.codex_protected_owner.is_some()));
        let originals = ["a.jsonl", "b.jsonl"].map(|name| {
            (
                name,
                fs::read_to_string(root.join("sessions").join(name)).unwrap(),
            )
        });
        for name in ["a.jsonl", "b.jsonl"] {
            fs::remove_file(root.join("sessions").join(name)).unwrap();
        }
        let healthy_owner = "ffffffff-1111-4111-8111-ffffffffffff";
        let body = member(healthy_owner, "healthy", 100, 100)
            .iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>();
        fs::write(root.join("sessions/c.jsonl"), body).unwrap();
        let (after, held) = scan(&root, previous.clone(), 3);
        assert!(!held.census_complete);
        assert_eq!(held.ownership_incomplete_file_count, 2);
        let (c, [unknown, _, _]) = held.causes.summary(held.ownership_incomplete_file_count);
        assert_eq!(c[ownership::ABSENT], 2);
        assert_eq!(c[..6].iter().sum::<usize>() + unknown, 2);
        assert!(held
            .snapshots
            .iter()
            .all(|item| item.source_session_id == healthy_owner));
        assert_eq!(
            held.snapshots.len(),
            1,
            "healthy physical owner remains uploadable"
        );
        for (key, entry) in &previous.files {
            assert_eq!(
                serde_json::to_value(&after.files[key]).unwrap(),
                serde_json::to_value(entry).unwrap()
            );
        }
        let counts = after.traversal.as_ref().unwrap().counts.clone();
        let causes = serde_json::to_value(
            counts
                .unreadable_causes
                .projection(counts.unreadable_path_count as u64),
        )
        .unwrap();
        assert_eq!(
            causes["counts"][6], 1,
            "one protected-absence event for newly missing group"
        );
        assert_eq!(causes["unattributed"], 0);

        let deadline = after
            .traversal
            .as_ref()
            .unwrap()
            .unhealthy_retry_not_before_unix_seconds;
        let quiet = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            after.clone(),
            "2026-10-06T23:00:00Z",
            7,
            3,
            false,
            None,
            &[],
            false,
            false,
        );
        assert!(
            quiet.codex_join_inventory.is_none(),
            "quiet red tick must not rescan headers"
        );
        let (quiet_index, quiet_result) = scan(&root, after.clone(), 3);
        assert_eq!(quiet_result.scanned_file_count, 0);
        assert_eq!(
            serde_json::to_value(&quiet_index.traversal.as_ref().unwrap().counts).unwrap(),
            serde_json::to_value(&counts).unwrap()
        );
        assert_eq!(
            quiet_index
                .traversal
                .as_ref()
                .unwrap()
                .unhealthy_retry_not_before_unix_seconds,
            deadline
        );
        // The existing age/missing-source reconciler cannot evict file-owned
        // selectors even when its observation set no longer includes the files.
        let mut aged = after;
        aged.traversal.as_mut().unwrap().observed_index_keys.clear();
        assert!(reconcile_missing_index_entries_with_limit(&mut aged, 10));
        for key in previous.files.keys() {
            assert!(aged.files.contains_key(key));
        }
        for (name, text) in originals {
            fs::write(root.join("sessions").join(name), text).unwrap();
        }
        fs::remove_file(root.join("logs_2.sqlite")).unwrap();
        aged.traversal
            .as_mut()
            .unwrap()
            .unhealthy_retry_not_before_unix_seconds = Some(0);
        let (recovered, restored) = scan(&root, aged, 3);
        assert!(
            restored.census_complete,
            "a due fresh census can clear the source-loss hold"
        );
        let priced_key = local_index_key(&root.join("sessions/b.jsonl"));
        assert_eq!(
            recovered.files[&priced_key].codex_applied_tier_receipt,
            previous.files[&priced_key].codex_applied_tier_receipt
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn protected_owner_blocks_state_only_replacement_without_claiming_other_owners() {
        let root = native_join_fixture_root(true);
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
        let mut metadata = CodexTitleMetadata::default();
        for id in [owner, healthy] {
            metadata.state_threads.insert(
                id.to_owned(),
                CodexStateThread {
                    tokens_used: 300,
                    ..CodexStateThread::default()
                },
            );
        }
        let mut items = Vec::new();
        assert_eq!(
            append_codex_state_only_snapshots(
                &mut items,
                &metadata,
                "2026-10-06T23:00:00Z",
                &mut index,
                &BTreeSet::new()
            ),
            Some((1, 0))
        );
        assert_eq!(items[0].source_session_id, healthy);
        // Malformed/future owner metadata cannot reset the surrounding index
        // and expose a previously protected owner to the fallback.
        let mut value = serde_json::to_value(&index).unwrap();
        let key = local_index_key(&root.join("sessions/b.jsonl"));
        value["files"][&key]["codex_protected_owner"] = json!({"future": true});
        let mut malformed: ScanIndex = serde_json::from_value(value).unwrap();
        assert_eq!(malformed.files.len(), index.files.len());
        let mut items = Vec::new();
        assert_eq!(
            append_codex_state_only_snapshots(
                &mut items,
                &metadata,
                "2026-10-06T23:00:00Z",
                &mut malformed,
                &BTreeSet::new()
            ),
            Some((0, 0))
        );
        assert!(items.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn missing_protected_receipt_rewrite_scope_change_or_cap_holds_correction() {
        let rows = member("owner", "r", 100, 100);
        let mut replay = TierReplay::new(None, false, "scope".into());
        for row in &rows {
            replay.observe(row);
        }
        replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
        let receipt = replay.finish().unwrap().unwrap();
        assert!(TierReplay::new(None, true, "scope".into())
            .finish()
            .is_err());
        let mut changed = rows.clone();
        changed[0]["payload"]["id"] = json!("other");
        for (rows, scope) in [
            (changed.as_slice(), "scope"),
            (rows.as_slice(), "other-scope"),
        ] {
            let mut replay = TierReplay::new(Some(receipt.clone()), true, scope.into());
            for row in rows {
                replay.observe(row);
            }
            replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
            assert!(replay.finish().is_err());
        }
        let mut replay = TierReplay::new(None, false, "scope".into());
        for i in 0..=MAX_APPLIED_TIERS {
            replay.admitted(Some((format!("{i:064x}"), "derived_from_logs_2".into())));
        }
        assert!(replay.finish().is_err());
    }
    #[test]
    fn malformed_or_missing_captured_metadata_holds_without_resetting_index() {
        for malformed in [Value::Null, json!({"version":"future","opaque":true})] {
            let root = native_join_fixture_root(true);
            let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
            finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
            let (mut captured, changed, held) =
                working.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
            assert_eq!(changed.len(), 1);
            assert!(held.is_empty());
            let path = root.join("capture.json");
            captured.save(&path).unwrap();
            let key = captured
                .files
                .iter()
                .find(|(_, entry)| entry.codex_captured_tier_receipt_required)
                .unwrap()
                .0
                .clone();
            let mut value = serde_json::to_value(&captured).unwrap();
            value["files"][&key]["codex_captured_tier_receipt"] = malformed;
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(
                loaded.files.len(),
                2,
                "receipt damage must not reset protected state"
            );
            fs::remove_file(root.join("logs_2.sqlite")).unwrap();
            let (after, held) = scan(&root, loaded, 2);
            assert!(held.snapshots.is_empty());
            assert_eq!(held.ownership_incomplete_file_count, 2);
            assert!(after.files[&key].codex_captured_uncommitted);
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn capture_cap_refuses_group_without_evicting_known_selectors() {
        let root = native_join_fixture_root(true);
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let entry = working
            .files
            .values()
            .find(|entry| entry.codex_applied_tier_receipt.is_some())
            .unwrap();
        let mut full = entry.clone();
        full.codex_applied_tier_receipt.as_mut().unwrap().tiers = (0..MAX_APPLIED_TIERS)
            .map(|n| {
                (
                    sha256_hex(&["synthetic-tier", &n.to_string()]),
                    "derived_from_logs_2".into(),
                )
            })
            .collect();
        let mut previous = ScanIndex::default();
        let bytes = full
            .codex_applied_tier_receipt
            .as_ref()
            .unwrap()
            .retained_bytes();
        for n in 0..=(MAX_RECEIPT_BYTES / bytes) {
            previous
                .files
                .insert(format!("synthetic-existing-{n}"), full.clone());
        }
        let before = serde_json::to_vec(&previous).unwrap();
        let (captured, changed, held) =
            working.stage_codex_recovery_capture(&previous, &result.snapshots);
        assert!(changed.is_empty());
        assert_eq!(held.len(), 1);
        assert_eq!(serde_json::to_vec(&captured).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn older_body_acceptance_or_rollback_cannot_discard_new_captured_facts() {
        let root = native_join_fixture_root(true);
        let (mut old_index, mut old_result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut old_result, &mut old_index);
        old_result.finish_codex_capture_boundary(&mut old_index);
        let old_accepted = old_result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous =
            old_index.committable_subset(&ScanIndex::default(), &old_accepted, &BTreeMap::new());
        let path = root.join("sessions/b.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        for row in member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 200, 500)
            .into_iter()
            .skip(1)
        {
            text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
        }
        fs::write(&path, text).unwrap();
        let (mut working, mut result) = scan(&root, previous.clone(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let (captured, changed, held) =
            working.stage_codex_recovery_capture(&previous, &result.snapshots);
        assert_eq!(changed.len(), 1);
        assert!(held.is_empty());
        let key = local_index_key(&path);
        assert_eq!(
            captured.files[&key]
                .codex_captured_tier_receipt
                .as_ref()
                .unwrap()
                .tiers
                .len(),
            2
        );
        for accepted in [&old_accepted, &BTreeSet::new()] {
            let mut rollback = captured.clone();
            rollback.reconcile_codex_recovery_settlement(&captured, accepted);
            assert_eq!(
                rollback.files[&key].codex_captured_tier_receipt,
                captured.files[&key].codex_captured_tier_receipt
            );
            assert_eq!(
                rollback.files[&key].codex_applied_tier_receipt,
                previous.files[&key].codex_applied_tier_receipt
            );
            let mut damaged = captured.clone();
            damaged
                .files
                .get_mut(&key)
                .unwrap()
                .codex_captured_tier_receipt = None;
            let mut rollback = damaged.clone();
            rollback.reconcile_codex_recovery_settlement(&damaged, accepted);
            assert!(rollback.files[&key].codex_captured_tier_receipt_required);
            assert!(rollback.files[&key].codex_captured_tier_receipt.is_none());
        }
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        working.reconcile_codex_recovery_settlement(&captured, &accepted);
        assert!(!working.files[&key].codex_captured_tier_receipt_required);
        assert_eq!(
            working.files[&key]
                .codex_applied_tier_receipt
                .as_ref()
                .unwrap()
                .tiers
                .len(),
            2
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pending_membership_expansion_loss_stale_ack_and_supported_correction() {
        let root = native_join_fixture_root(false);
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let (mut first, mut result) = scan(&root, ScanIndex::default(), 3);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut first);
        let old_accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let (pending, _, _) =
            first.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
        assert_eq!(pending.files.len(), 2);
        assert!(pending.current_snapshot_fingerprints().is_empty());
        let text = member(owner, "r-c", 100, 400)
            .iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>();
        fs::write(root.join("sessions/c.jsonl"), text).unwrap();
        let (mut expanded, mut result) = scan(&root, pending.clone(), 3);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut expanded);
        assert_eq!(result.snapshots.len(), 3);
        let (new_pending, changed, held) =
            expanded.stage_codex_recovery_capture(&pending, &result.snapshots);
        assert_eq!(changed.len(), 1);
        assert!(held.is_empty());
        assert_eq!(new_pending.files.len(), 3);
        let mut stale = first.clone();
        stale.reconcile_codex_recovery_settlement(&new_pending, &old_accepted);
        for (key, entry) in &stale.files {
            assert_eq!(
                entry.codex_captured_joined_member_set,
                new_pending.files[key].codex_captured_joined_member_set
            );
        }
        fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
        let (held_index, held) = scan(&root, new_pending.clone(), 3);
        assert!(held.snapshots.is_empty());
        assert!(!held.census_complete);
        assert_eq!(held_index.files.len(), 3);
        // All known physical members present and independently proved: a real
        // correction may replace usage, rather than waiting for a timeout.
        let rows = member(owner, "r-b", 50, 150);
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let rows = member(owner, "r-c", 100, 250);
        fs::write(
            root.join("sessions/c.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let (mut corrected, mut result) = scan(&root, new_pending.clone(), 3);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut corrected);
        assert_eq!(result.snapshots.len(), 3);
        assert!(result.snapshots.iter().all(|item| item.input_tokens == 250));
        let (capture, _, held) =
            corrected.stage_codex_recovery_capture(&new_pending, &result.snapshots);
        assert!(held.is_empty());
        result.finish_codex_capture_boundary(&mut corrected);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let settled = corrected.committable_subset(&capture, &accepted, &BTreeMap::new());
        assert!(settled.files.values().all(|entry| entry
            .codex_captured_joined_member_set
            .is_none()
            && !entry.codex_captured_uncommitted
            && entry.codex_joined_member_set.is_some()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pending_membership_cap_and_unknown_version_preserve_protected_state() {
        let root = native_join_fixture_root(false);
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let (captured, _, _) =
            working.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
        let mut full = ScanIndex::default();
        let sample = captured.files.values().next().unwrap();
        for n in 0..MAX_HEADER_FILES {
            full.files
                .insert(format!("synthetic-pending-{n}"), sample.clone());
        }
        let (after, changed, held) = working.stage_codex_recovery_capture(&full, &result.snapshots);
        assert!(changed.is_empty());
        assert_eq!(held.len(), 1);
        assert_eq!(after.files.len(), MAX_HEADER_FILES);
        assert_eq!(
            serde_json::to_vec(&after).unwrap(),
            serde_json::to_vec(&full).unwrap()
        );
        for malformed in [
            json!("codex_captured_join:v2:future"),
            json!({"opaque":true}),
            Value::Null,
        ] {
            let mut value = serde_json::to_value(&captured).unwrap();
            let key = captured.files.keys().next().unwrap();
            value["files"][key]["codex_captured_joined_member_set"] = malformed;
            let path = root.join("malformed.json");
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(loaded.files.len(), 2);
            let (_, result) = scan(&root, loaded, 2);
            assert!(result.snapshots.is_empty());
            assert!(!result.census_complete);
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pending_correction_return_to_old_accepted_body_is_not_a_noop() {
        let root = native_join_fixture_root(false);
        let path = root.join("sessions/b.jsonl");
        let original = fs::read(&path).unwrap();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let old_accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let previous =
            index.committable_subset(&ScanIndex::default(), &old_accepted, &BTreeMap::new());
        let rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 400, 500);
        fs::write(
            &path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let (mut working, mut result) = scan(&root, previous.clone(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        assert!(result.snapshots.iter().all(|item| item.input_tokens == 500));
        let (pending, _, _) = working.stage_codex_recovery_capture(&previous, &result.snapshots);
        // The server may hold500 after a lost response. The old local300 ACK
        // therefore cannot suppress an independently proved return to300.
        fs::write(&path, original).unwrap();
        let (mut corrected, mut result) = scan(&root, pending.clone(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut corrected);
        assert_eq!(
            result.snapshots.len(),
            2,
            "pending capture must not suppress a correction to an older body"
        );
        assert!(result.snapshots.iter().all(|item| item.input_tokens == 300));
        let (capture, changed, held) =
            corrected.stage_codex_recovery_capture(&pending, &result.snapshots);
        assert_eq!(changed.len(), 1);
        assert!(held.is_empty());
        result.finish_codex_capture_boundary(&mut corrected);
        let settled = corrected.committable_subset(&capture, &old_accepted, &BTreeMap::new());
        assert!(settled
            .files
            .values()
            .all(|entry| entry.codex_captured_joined_member_set.is_none()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn historical_replay_preserves_pending_and_applied_protection() {
        for priority in [false, true] {
            for applied in [false, true] {
                let root = native_join_fixture_root(priority);
                let rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 100, 400);
                fs::write(
                    root.join("sessions/c.jsonl"),
                    rows.iter()
                        .map(|row| serde_json::to_string(row).unwrap() + "\n")
                        .collect::<String>(),
                )
                .unwrap();
                let (mut index, mut result) = scan(&root, ScanIndex::default(), 3);
                finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
                let (capture, _, _) =
                    index.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
                result.finish_codex_capture_boundary(&mut index);
                let accepted = result
                    .snapshots
                    .iter()
                    .map(|item| item.snapshot_fingerprint.clone())
                    .collect();
                let mut previous = if applied {
                    index.committable_subset(&capture, &accepted, &BTreeMap::new())
                } else {
                    capture
                };
                let before = previous.clone();
                previous.prepare_historical_replay("new-context-curve-replay".into());
                assert_eq!(
                    previous.files.len(),
                    3,
                    "replay must retain file-owned recovery facts"
                );
                for (key, entry) in &previous.files {
                    let old = &before.files[key];
                    assert_eq!(entry.codex_joined_member_set, old.codex_joined_member_set);
                    assert_eq!(
                        entry.codex_captured_joined_member_set,
                        old.codex_captured_joined_member_set
                    );
                    assert_eq!(
                        entry.codex_applied_tier_receipt,
                        old.codex_applied_tier_receipt
                    );
                    assert_eq!(
                        entry.codex_captured_tier_receipt,
                        old.codex_captured_tier_receipt
                    );
                    assert!(entry.last_snapshot_fingerprint.is_none());
                    assert!(entry.last_upload_body_witness.is_none());
                }
                assert!(previous.current_snapshot_fingerprints().is_empty());
                if priority {
                    fs::remove_file(root.join("logs_2.sqlite")).unwrap();
                }
                let (mut rebuilt, mut result) = scan(&root, previous.clone(), 3);
                finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut rebuilt);
                assert_eq!(
                    result.snapshots.len(),
                    3,
                    "intact protected replay must reoffer all aliases"
                );
                assert!(result.snapshots.iter().all(|item| item.input_tokens == 400));
                let healthy = member("bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee", "healthy", 100, 100);
                fs::write(
                    root.join("sessions/d.jsonl"),
                    healthy
                        .iter()
                        .map(|row| serde_json::to_string(row).unwrap() + "\n")
                        .collect::<String>(),
                )
                .unwrap();
                fs::remove_file(root.join("sessions/c.jsonl")).unwrap();
                let (held_index, result) = scan(&root, previous, 3);
                assert!(!result.census_complete);
                assert_eq!(result.snapshots.len(), 1);
                assert_eq!(
                    result.snapshots[0].source_session_id,
                    "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                );
                assert_eq!(held_index.files.len(), 4);
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
    #[test]
    fn native_group_reports_finite_scan_capture_and_restart_cost() {
        let root = native_join_fixture_root(true);
        let start = std::time::Instant::now();
        let ((mut index, mut result), stats) =
            crate::retry_allocation_probe::measure(|| scan(&root, ScanIndex::default(), 2));
        let scan_micros = start.elapsed().as_micros();
        let header_bytes = result
            .codex_join_validation
            .as_ref()
            .unwrap()
            .inventory
            .read_bytes;
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        result.finish_codex_capture_boundary(&mut index);
        let (capture, _, _) =
            index.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
        result.finish_codex_capture_boundary(&mut index);
        let capture_bytes = serde_json::to_vec(&capture).unwrap().len();
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let settled = index.committable_subset(&capture, &accepted, &BTreeMap::new());
        let index_bytes = serde_json::to_vec(&settled).unwrap().len();
        let path = root.join("measured-index.json");
        let mut settled = settled;
        settled.save(&path).unwrap();
        fs::remove_file(root.join("logs_2.sqlite")).unwrap();
        let start = std::time::Instant::now();
        let (_, restart) = scan(&root, ScanIndex::load(&path).unwrap(), 2);
        assert!(restart.snapshots.is_empty());
        assert_eq!(restart.semantic_noop_count, 2);
        eprintln!(
            "CODEX_UNION_MEASUREMENT {}",
            json!({"synthetic_members":2,
            "selected_parser_passes":2,"header_read_bytes":header_bytes,
            "scan_microseconds":scan_micros,"scan_requested_allocation_peak":stats.requested_peak,
            "scan_usable_allocation_peak":stats.usable_peak,"capture_index_bytes":capture_bytes,
            "settled_index_bytes":index_bytes,"restart_microseconds":start.elapsed().as_micros(),
            "restart_semantic_noops":restart.semantic_noop_count,"restart_full_replays":0})
        );
        fs::remove_dir_all(root).unwrap();
    }
    pub(crate) fn legacy_index(
        inventory: &HeaderInventory,
        traces: Option<Arc<CodexTurnTraceMap>>,
    ) -> ScanIndex {
        let mut index = ScanIndex::default();
        for member in inventory
            .groups()
            .into_values()
            .flat_map(|group| group.members)
        {
            let mut census = ScanCensus::default();
            let (member, file) = open_and_identify_scan_candidate(
                SnapshotSource::Codex,
                member,
                &mut census,
                None,
                0,
                crate::snapshots::DiscoveryRetention::unverified(&BTreeMap::new()),
            )
            .unwrap();
            let parsed = parse_opened_jsonl_file(
                file,
                &member.opened_object_identity,
                &member.path,
                "2026-10-06T23:00:00Z",
                member.source_file_fingerprint.clone(),
                SnapshotSource::Codex,
                apply_codex_line,
                Some(&CodexTitleMetadata::default()),
                None,
                traces.clone(),
                None,
                false,
                None,
                false,
            )
            .unwrap();
            assert!(parsed.complete());
            let fingerprints = parsed
                .snapshots
                .iter()
                .map(|item| snapshot_fingerprint(SnapshotSource::Codex, item))
                .collect::<BTreeSet<_>>();
            let key = local_index_key(&member.path);
            index.record(
                member,
                Some(snapshot_file_entity_set_hex(&fingerprints)),
                ScanParseOutcome::Snapshot,
            );
            index.file_snapshot_fingerprints.insert(key, fingerprints);
        }
        index
    }
    #[test]
    fn legacy_proof_refreshes_expired_launch_lookup_without_consuming_completed_proof() {
        let (root, inventory) = fixture();
        let previous = legacy_index(&inventory, None);
        let group = inventory.groups().into_values().next().unwrap();
        let workers = vec![group.owner.clone()];
        let key = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [13_u8; 32],
        );
        let context = crate::session_attribution::SessionAttributionContext::from_activity_hint(
            SnapshotSource::Codex,
            &root,
            true,
            Some(&key),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap();
        let metadata = CodexTitleMetadata::default();
        let mut boot = GroupBoot::new(group, &previous);
        loop {
            match boot.step(Some(&context), &previous) {
                Boot::Pending => {}
                Boot::Ready => break,
                _ => panic!("the legacy group boots"),
            }
        }
        assert!(context.launches_prepared(&workers));
        context.expire_launch_lookup_for_test();
        assert!(!context.launches_prepared(&workers));
        let events = root.join(".ottto/launch-events/processed");
        fs::create_dir_all(&events).unwrap();
        for n in 1..=600 {
            let raw = json!({"schema":"agent_launch.v1",
                "controller_session_ref":"11111111-2222-4333-8444-555555555555",
                "worker_session_ref":format!("{n:08x}-2222-4333-8444-555555555555"),
                "relationship_kind":"launched", "workflow_ref":null, "pr_ref":null,
                "launch_ts":"2026-10-01T10:00:00Z",
                "capture_source":"launcher_event:opus_cli_agent", "evidence":"direct"})
            .to_string();
            let event = crate::launch_events::validate_event(&raw).unwrap();
            fs::write(
                events.join(format!(
                    "{}.json",
                    crate::launch_events::event_digest(&event)
                )),
                raw,
            )
            .unwrap();
        }
        let mut job = boot
            .into_job(JobInputs {
                metadata: &metadata,
                traces: None,
                ledgers: None,
                artifacts: false,
                context_curve: false,
                index: &previous,
            })
            .unwrap();
        let no_scope = |_: &CandidateFile| None;
        let inputs = StepInputs {
            metadata: &metadata,
            attribution: Some(&context),
            artifacts: false,
            context_curve: false,
            live_scope: &no_scope,
        };
        let (mut steps, mut yields) = (0, 0);
        loop {
            let before = (
                job.group.as_ref().unwrap().current,
                job.parser.reader.consumed_bytes(),
            );
            match step_group(&mut job, &inputs) {
                GroupStep::Read(Ok(true)) => break,
                GroupStep::Read(Ok(false)) => {}
                _ => panic!("the legacy group replays"),
            }
            let after = (
                job.group.as_ref().unwrap().current,
                job.parser.reader.consumed_bytes(),
            );
            if before == after && job.parser.reader.finished {
                // A finished member re-entered its EOF: the lookup yielded.
                yields += 1;
            }
            steps += 1;
            assert!(steps < 100);
        }
        assert!(yields > 0, "lookup must yield across the retained backlog");
        assert_eq!(
            job.parser.reader.report.parsed_json_line_count, 6,
            "completed members must not be read twice"
        );
        assert_eq!(job.group.as_mut().unwrap().take_legacy_baselines().len(), 2);
        assert!(context.launches_prepared(&workers));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_first_import_requires_actual_old_output_match_and_allows_healthy_sibling() {
        let (root, inventory) = fixture();
        let previous = legacy_index(&inventory, None);
        let (mut index, mut result) = scan(&root, previous.clone(), 2);
        assert_eq!(result.codex_legacy_join_baselines.len(), 2);
        result.reconcile_codex_legacy_joining(&mut index, &previous, "machine", |_, _| {});
        assert!(result.census_complete);
        assert_eq!(result.snapshots.len(), 2);
        fs::remove_dir_all(root).unwrap();
        let (root, inventory) = fixture();
        let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let mut rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
        rows.insert(
            1,
            json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
        );
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let mut traces = CodexTurnTraceMap::default();
        traces.priority_turns.insert(turn.into());
        let previous = legacy_index(&inventory, Some(Arc::new(traces)));
        let sibling = member(
            "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "r-sibling",
            100,
            100,
        );
        fs::write(
            root.join("sessions/sibling.jsonl"),
            sibling
                .iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let (mut index, mut result) = scan(&root, previous.clone(), 3);
        result.reconcile_codex_legacy_joining(&mut index, &previous, "machine", |_, _| {});
        assert!(!result.census_complete);
        assert_eq!(
            result.snapshots.len(),
            1,
            "only the mismatched legacy group is held"
        );
        assert_eq!(
            result.snapshots[0].source_session_id,
            "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        );
        for (key, entry) in &previous.files {
            assert_eq!(
                index.files[key].last_snapshot_fingerprint,
                entry.last_snapshot_fingerprint
            );
        }
        assert!(index
            .traversal
            .as_ref()
            .unwrap()
            .unhealthy_retry_not_before_unix_seconds
            .is_some());
        let (_index, quiet) = scan(&root, index, 3);
        assert!(quiet.snapshots.is_empty());
        assert_eq!(
            quiet.scanned_file_count, 0,
            "held unchanged group uses existing retry backoff"
        );
        fs::remove_dir_all(root).unwrap();
    }
    const OWNER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    /// Feed members in order through one `StreamProof`, with the parser's
    /// S10 tap after every UI usage record.
    pub(crate) fn stream(members: &[Vec<Value>]) -> Option<(JoinRefusal, usize)> {
        let mut proof = StreamProof::new(
            OWNER.into(),
            false,
            vec![MemberPlan::default(); members.len()],
        );
        for (position, rows) in members.iter().enumerate() {
            proof.begin_member(position);
            for row in rows {
                proof.observe(row);
                if codex_last_usage(row).is_some() {
                    let identity = codex_usage_event_identity(row);
                    proof.admitted_usage(row, true, identity.as_deref(), None);
                }
            }
            proof.end_member(0);
        }
        proof.finish_group();
        proof.refusal()
    }
    #[test]
    fn disjoint_continuation_uses_counter_order() {
        let a = member(OWNER, "response-a", 100, 100);
        let b = member(OWNER, "response-b", 200, 300);
        assert_eq!(stream(&[a.clone(), b.clone()]), None);
        let probes = [probe_before(&b[1]), probe_before(&a[1])];
        assert_eq!(order_by_probes(&[0, 1], &probes), Ok(vec![1, 0]));
    }
    #[test]
    fn overlapping_identity_gap_reset_or_different_owner_is_refused() {
        let a = member(OWNER, "response-a", 100, 100);
        for (b, reason) in [
            (member(OWNER, "response-a", 200, 300), JoinRefusal::Overlap),
            (member(OWNER, "response-b", 200, 400), JoinRefusal::Gap),
            (member(OWNER, "response-b", 200, 200), JoinRefusal::Overlap),
            (
                member(
                    "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "response-b",
                    200,
                    300,
                ),
                JoinRefusal::Overlap,
            ),
        ] {
            assert_eq!(stream(&[a.clone(), b]), Some((reason, 1)));
        }
    }
    #[test]
    fn copied_ui_contribution_cannot_gain_a_second_member() {
        let a = member(OWNER, "response-a", 100, 100);
        let mut b = member(OWNER, "response-b", 100, 200);
        b[2] = a[2].clone();
        assert_eq!(stream(&[a, b]), Some((JoinRefusal::Overlap, 1)));
    }
    #[test]
    fn missing_owner_native_fields_or_ui_coverage_is_not_accepted() {
        let rows = member(OWNER, "response", 100, 100);
        for field in ["thread_id", "response_id", "usage", "thread_token_usage"] {
            let mut changed = rows.clone();
            changed[1]["payload"].as_object_mut().unwrap().remove(field);
            assert_eq!(
                stream(&[changed]),
                Some((JoinRefusal::Corrupt, 0)),
                "{field}"
            );
        }
        let mut changed = rows;
        changed[2]["payload"]["info"]["last_token_usage"] = usage(200);
        assert_eq!(stream(&[changed]), Some((JoinRefusal::UiUnmatched, 0)));
    }
}

#[cfg(all(test, unix))]
pub(in crate::snapshots) mod header_cache_tests {
    use super::*;
    thread_local! {
        pub(in crate::snapshots) static READ_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        static CACHE_OPERATIONS: std::cell::RefCell<Option<Vec<(&'static str, String)>>> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn cache_operation(operation: &'static str, key: &str) {
        CACHE_OPERATIONS.with(|calls| {
            if let Some(calls) = calls.borrow_mut().as_mut() {
                calls.push((operation, key.to_owned()));
            }
        });
    }
    fn cache_operations<T>(run: impl FnOnce() -> T) -> (T, Vec<(&'static str, String)>) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                CACHE_OPERATIONS.with(|calls| *calls.borrow_mut() = None);
            }
        }
        CACHE_OPERATIONS.with(|calls| {
            assert!(calls.borrow().is_none());
            *calls.borrow_mut() = Some(Vec::new());
        });
        let _reset = Reset;
        let result = run();
        let calls = CACHE_OPERATIONS.with(|calls| calls.borrow_mut().take().unwrap());
        (result, calls)
    }
    pub(in crate::snapshots) fn page(
        root: &Path,
        paths: &BTreeSet<String>,
        cache: &sampled_scan::SharedCache,
    ) -> HeaderInventory {
        let sessions = root.join("sessions");
        let mut census = DirectoryCensus::new();
        census.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], paths, Some(&census));
        while !inventory.step_cached(&CodexTitleMetadata::default(), Some(cache)) {}
        inventory
    }
    fn assert_charge(cache: &HeaderCache) {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        let mut summary = Counter::new(usize::MAX);
        cache.charge(&mut summary).unwrap();
        let mut walked = Counter::new(usize::MAX);
        cache.completed_heap_bound(&mut walked).unwrap();
        assert_eq!(summary.bytes, walked.bytes);
        assert!(summary.visits_for_test() < 10);
    }
    fn paths(inventory: &HeaderInventory) -> BTreeSet<String> {
        inventory
            .headers
            .iter()
            .map(|header| local_index_key(&header.candidate.path))
            .collect()
    }
    fn facts(inventory: &HeaderInventory) -> Vec<(String, String, Option<i64>)> {
        inventory
            .headers
            .iter()
            .map(|header| {
                (
                    local_index_key(&header.candidate.path),
                    header.owner.clone(),
                    header.created_unix_ms,
                )
            })
            .collect()
    }
    #[test]
    fn warm_plain_facts_never_cover_archives_and_changed_archive_stamp_is_revalidated() {
        use codex_compressed_input::{
            ArchiveDisposition, ArchiveEvidence, HeaderWork, ValidatedHeader,
        };
        let _lock = codex_compressed_input::tests::DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let cold = page(&root, &paths, &cache);
        assert_eq!(cold.reuse_misses, paths.len());
        assert_eq!(page(&root, &paths, &cache).reuse_hits, paths.len());
        let plain_key = paths.first().unwrap();
        let facts = cache
            .with_cursor(|cursor| cursor.headers.get(plain_key))
            .unwrap()
            .unwrap();
        let archive = root.join("sessions/rollout-cached-archive.jsonl.zst");
        fs::write(&archive, b"archive-old-stamp").unwrap();
        let key = local_index_key(&archive);
        // Both boundaries deny even perfectly valid warm plain facts under an
        // archive key, and lookup refuses a hypothetical stale RAM entry too.
        cache.refresh_header(key.clone(), Some(facts.clone()));
        assert!(cache
            .with_cursor(|cursor| cursor.headers.get(&key))
            .unwrap()
            .is_none());
        cache
            .with_cursor(|cursor| assert!(!cursor.headers.entries.contains_key(&key)))
            .unwrap();
        let mut stale = HeaderCache::default();
        stale.entries.insert(key.clone(), facts);
        assert!(stale.get(&key).is_none());
        let header = ValidatedHeader::from_bytes(
            b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"cached-archive\"}}\n",
        )
        .unwrap();
        let mut evidence =
            ArchiveEvidence::begin(&File::open(&archive).unwrap(), &archive, None).unwrap();
        evidence.header_validated = Some(header);
        evidence.disposition = ArchiveDisposition::HeaderValidated;
        let mut saved = serde_json::to_value(evidence).unwrap();
        saved["header_attempted"] = serde_json::json!(true);
        let evidence: ArchiveEvidence = serde_json::from_value(saved).unwrap();
        let mut index = ScanIndex::default();
        index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
        let before = serde_json::to_value(&index.files[&key]).unwrap();
        let candidate = codex_zst_refusal_tests::candidate(&archive);
        let mut work = HeaderWork {
            allowed: true,
            cpu_micros: 30_000_000,
            ..Default::default()
        };
        // Same-stamp ArchiveEvidence, independently of the warm plain cache,
        // can supply metadata before the fresh-decode CPU gate.
        assert_eq!(
            index
                .inventory_archive_header(&candidate, Some(&cache), &mut work)
                .unwrap()
                .1,
            0
        );
        assert!(index.archive_header(&archive).is_some());
        let mut all = paths.clone();
        all.insert(key.clone());
        let run = |index: &mut ScanIndex| {
            let sessions = root.join("sessions");
            let mut census = DirectoryCensus::new();
            census.observe(&sessions, &fs::metadata(&sessions).unwrap());
            let mut inventory = HeaderInventory::new(&[sessions], &all, Some(&census));
            inventory.archive_work.allowed = true;
            inventory.archive_work.cpu_micros = 30_000_000;
            while !inventory.step_with_archive(&CodexTitleMetadata::default(), index, Some(&cache))
            {
            }
            inventory
        };
        let constructions = codex_zst_refusal_tests::decoder_construction_count();
        let same = run(&mut index);
        assert!(same.complete);
        assert_eq!(same.reuse_hits, paths.len());
        assert_eq!(
            same.reuse_misses, 0,
            "archives are outside plain cache accounting"
        );
        assert_eq!(same.headers.len(), paths.len() + 1);
        assert_eq!(same.read_bytes, 0);
        fs::OpenOptions::new()
            .append(true)
            .open(&archive)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        assert!(
            index.archive_header(&archive).is_none(),
            "archive's own stamp invalidates the old header"
        );
        assert!(!index.files[&key]
            .archive
            .as_ref()
            .unwrap()
            .matches(&File::open(&archive).unwrap()));
        // FD mismatch must reach the CPU refusal rather than return the stale
        // ArchiveEvidence header or any warm plain-cache fact; no decoder paid.
        assert!(index
            .inventory_archive_header(&candidate, Some(&cache), &mut work)
            .is_err());
        let changed = run(&mut index);
        assert!(!changed.complete);
        assert!(changed.refused.contains_key(&key));
        assert!(changed.headers.iter().all(|h| h.candidate.path != archive));
        assert_eq!(changed.reuse_hits, paths.len());
        assert_eq!(changed.reuse_misses, 0);
        assert_eq!(changed.read_bytes, 0);
        assert_eq!(
            codex_zst_refusal_tests::decoder_construction_count(),
            constructions
        );
        assert_eq!(serde_json::to_value(&index.files[&key]).unwrap(), before);
        cache
            .with_cursor(|cursor| assert!(!cursor.headers.entries.contains_key(&key)))
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn warm_plain_facts_are_skipped_before_lookup_when_the_file_becomes_decode_held() {
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        page(&root, &paths, &cache);
        let held = paths.first().unwrap();
        assert!(cache
            .with_cursor(|cursor| cursor.headers.get(held))
            .unwrap()
            .is_some());
        let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
        value["files"][held] = serde_json::json!({"unknown": 1});
        let mut index = lenient_decode::read_bounded(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(index.decode_holds_file(held));
        let before = serde_json::to_value(&index).unwrap();
        let sessions = root.join("sessions");
        let mut census = DirectoryCensus::new();
        census.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&census));
        READ_CALLS.with(|calls| calls.set(0));
        let (_, operations) = cache_operations(|| {
            while !inventory.step_with_archive(
                &CodexTitleMetadata::default(),
                &mut index,
                Some(&cache),
            ) {}
        });
        assert!(
            inventory.complete,
            "cold headers restore parent inventory semantics"
        );
        assert_eq!(inventory.reuse_hits, paths.len() - 1);
        assert_eq!(inventory.reuse_misses, 1);
        assert!(!inventory.refused.contains_key(held));
        assert!(inventory
            .headers
            .iter()
            .any(|h| local_index_key(&h.candidate.path) == *held));
        assert!(operations.iter().all(|(_, key)| key != held));
        assert!(operations.iter().any(|(operation, _)| *operation == "get"));
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 1));
        assert_eq!(
            serde_json::to_value(&index).unwrap(),
            before,
            "custody unchanged"
        );
        // The unknown raw owner still blocks selection globally downstream;
        // inventory itself follows the parents' cold-read path. No held-file
        // fact was inserted or refreshed, and unholding needs no further read.
        READ_CALLS.with(|calls| calls.set(0));
        let repaired = page(&root, &paths, &cache);
        assert!(repaired.complete);
        assert_eq!(repaired.reuse_hits, paths.len());
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn decode_held_owner_uses_cold_headers_and_unrelated_growth_emits_with_warm_facts() {
        use std::io::Write;
        for known_owner in [true, false] {
            let (root, fixture) = tests::fixture();
            let owner = fixture.headers[0].owner.clone();
            let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
            let healthy_path = root
                .join("sessions")
                .join(format!("rollout-{healthy}.jsonl"));
            let rows = tests::member(healthy, "healthy-first", 100, 100);
            fs::write(
                &healthy_path,
                rows.iter()
                    .map(|row| row.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            let (mut previous, mut initial) = tests::scan(&root, ScanIndex::default(), 100);
            assert!(initial.census_complete);
            assert!(initial
                .snapshots
                .iter()
                .any(|item| item.source_session_id == healthy && item.input_tokens == 100));
            finalize_scan_after_policy(SnapshotSource::Codex, &mut initial, &mut previous);
            initial.finish_codex_capture_boundary(&mut previous);
            let accepted = initial
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect();
            previous =
                previous.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
            let healthy_key = local_index_key(&healthy_path);
            assert!(previous.files.contains_key(&healthy_key));
            assert!(previous.files[&healthy_key]
                .codex_joined_member_set
                .is_none());
            assert!(previous.files[&healthy_key]
                .codex_applied_tier_receipt
                .is_none());
            let mut paths = paths(&fixture);
            paths.insert(healthy_key.clone());
            let held = local_index_key(&fixture.headers[0].candidate.path);
            let cache = Arc::new(sampled_scan::SharedCache::default());
            assert!(page(&root, &paths, &cache).complete);
            assert_eq!(page(&root, &paths, &cache).reuse_hits, paths.len());
            let old_len = fs::metadata(&healthy_path).unwrap().len();
            let growth = tests::member(healthy, "healthy-growth", 100, 200)
                .into_iter()
                .skip(1)
                .map(|row| row.to_string() + "\n")
                .collect::<String>();
            fs::OpenOptions::new()
                .append(true)
                .open(&healthy_path)
                .unwrap()
                .write_all(growth.as_bytes())
                .unwrap();
            assert!(fs::metadata(&healthy_path).unwrap().len() > old_len);
            let mut wire = serde_json::to_value(&previous).unwrap();
            wire["files"][&held] = serde_json::json!({"unknown": 1});
            if known_owner {
                wire["files"][&held]["codex_protected_owner"] =
                    serde_json::json!(codex_protected_owner(&owner));
            }
            let index = lenient_decode::read_bounded(&serde_json::to_vec(&wire).unwrap()).unwrap();
            assert!(index.decode_holds_file(&held));
            assert_eq!(
                index.decode_held_codex_owners().any(|o| o.is_none()),
                !known_owner
            );
            let raw_held = serde_json::to_value(&index).unwrap()["files"][&held].clone();
            let mut owned = OwnedSourceScan::new(
                SnapshotSource::Codex,
                &[root.join("sessions")],
                index,
                "2026-10-06T23:00:00Z",
                7,
                100,
                false,
                None,
                &[],
                false,
                false,
            );
            // Feed the production scanner its real completed inventory using
            // warm RAM facts. Body acquisition remains the ordinary portable
            // path; this does not require native sampled-decoder layout.
            let ((mut index, mut scan), reads) = tests::header_reads(|| {
                let mut inventoried = false;
                for _ in 0..1000 {
                    if !inventoried {
                        if let Some(inventory) = owned.codex_join_inventory.as_mut() {
                            let before = serde_json::to_value(&owned.index).unwrap();
                            let (_, operations) = cache_operations(|| {
                                while !inventory.step_with_archive(
                                    &CodexTitleMetadata::default(),
                                    &mut owned.index,
                                    Some(&cache),
                                ) {}
                            });
                            assert_eq!(serde_json::to_value(&owned.index).unwrap(), before);
                            assert!(inventory.complete);
                            assert!(inventory.refused.is_empty());
                            assert_eq!(inventory.reuse_hits, paths.len() - 2);
                            assert_eq!(inventory.reuse_misses, 2);
                            assert_eq!(
                                inventory.owner_for_path(Path::new(&held)),
                                Some(owner.as_str())
                            );
                            assert!(
                                operations.iter().all(|(_, key)| key != &held),
                                "held key has no cache lookup, invalidation or insertion"
                            );
                            assert!(operations.iter().any(|(operation, _)| *operation == "get"));
                            inventoried = true;
                        }
                    }
                    match owned.step(None) {
                        OwnedSourceScanStep::Pending(next) => owned = next,
                        OwnedSourceScanStep::Complete { index, scan, .. } => {
                            assert!(inventoried);
                            return (index, scan);
                        }
                    }
                }
                panic!("held-owner scan did not finish");
            });
            assert_eq!(
                reads.get(Path::new(&held)),
                Some(&1),
                "exactly the existing cold header read"
            );
            assert!(
                scan.snapshots
                    .iter()
                    .all(|item| item.source_session_id != owner),
                "held group never publishes"
            );
            assert_eq!(
                serde_json::to_value(&index).unwrap()["files"][&held],
                raw_held
            );
            finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
            scan.finish_codex_capture_boundary(&mut index);
            if known_owner {
                let emitted = scan
                    .snapshots
                    .iter()
                    .filter(|item| item.source_session_id == healthy)
                    .collect::<Vec<_>>();
                assert_eq!(emitted.len(), 1, "unrelated growing file emits its body");
                assert_eq!(emitted[0].input_tokens, 200);
                assert!(scan.codex_join_validation.is_none(),
                    "held group has no completed join proof; current inventory completeness was asserted before selection");
            } else {
                assert!(
                    scan.snapshots.is_empty(),
                    "unknown raw owner retains the parents' global selection hold"
                );
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn warm_plain_facts_do_not_cache_custody_or_same_owner_fences() {
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let warm = page(&root, &paths, &cache);
        let held = paths.first().unwrap();
        let owner = warm.owner_for_path(Path::new(held)).unwrap().to_owned();
        assert!(cache
            .with_cursor(|cursor| cursor.headers.get(held))
            .unwrap()
            .is_some());
        let mut index = ScanIndex::default();
        index.hold_compressed(
            Path::new(held),
            BTreeSet::from([owner.clone()]),
            CodexZstCause::ParentLedgerUnbound,
        );
        let before = serde_json::to_value(&index).unwrap();
        let sessions = root.join("sessions");
        let mut census = DirectoryCensus::new();
        census.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&census));
        READ_CALLS.with(|calls| calls.set(0));
        while !inventory.step_with_archive(&CodexTitleMetadata::default(), &mut index, Some(&cache))
        {
        }
        assert_eq!(inventory.reuse_hits, paths.len() - 1);
        assert_eq!(inventory.reuse_misses, 0);
        assert!(inventory
            .headers
            .iter()
            .all(|h| local_index_key(&h.candidate.path) != *held));
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        assert_eq!(serde_json::to_value(&index).unwrap(), before);
        while !inventory.prepare_custody(&index) {}
        assert!(!inventory.complete_for(Some(&owner)));
        assert!(
            inventory.groups().is_empty(),
            "same-owner debt is rebuilt from custody"
        );
        // A new index without custody uses the same warm facts, but inherits no
        // held cause, owner fence, membership exclusion or incompleteness.
        let clear = page(&root, &paths, &cache);
        assert!(clear.complete_for(Some(&owner)));
        assert_eq!(clear.reuse_hits, paths.len());
        assert!(clear.headers.iter().all(|h| h.custody_cause.is_none()));
        assert_eq!(
            clear
                .groups()
                .values()
                .map(|g| g.members.len())
                .sum::<usize>(),
            paths.len()
        );
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unchanged_pages_reuse_without_reading_and_restart_is_cold() {
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = sampled_scan::SharedCache::default();
        let first = page(&root, &paths, &cache);
        assert!(first.complete);
        assert_eq!(first.reuse_misses, paths.len());
        assert!(first.read_bytes > 0);
        READ_CALLS.with(|calls| calls.set(0));
        let second = page(&root, &paths, &cache);
        assert!(second.complete);
        assert_eq!(second.reuse_hits, paths.len());
        assert_eq!(second.reuse_misses, 0);
        assert_eq!(second.reuse_evictions, 0);
        assert_eq!(second.read_bytes, 0);
        assert_eq!(second.bytes_avoided, first.read_bytes);
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        assert_eq!(facts(&first), facts(&second));
        let cold = page(&root, &paths, &sampled_scan::SharedCache::default());
        assert_eq!(facts(&cold), facts(&second));
        assert_eq!(cold.read_bytes, first.read_bytes);
        READ_CALLS.with(|calls| assert_eq!(calls.get(), paths.len()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn growth_and_replacement_refresh_once_failures_never_become_hits() {
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = sampled_scan::SharedCache::default();
        page(&root, &paths, &cache);
        let path = Path::new(paths.first().unwrap());
        let original = fs::read(path).unwrap();
        let mut grown = original.clone();
        grown.extend_from_slice(b"{}\n");
        fs::write(path, &grown).unwrap();
        READ_CALLS.with(|calls| calls.set(0));
        let growth = page(&root, &paths, &cache);
        assert_eq!(growth.reuse_misses, 1);
        assert_eq!(growth.reuse_hits, 1);
        assert_eq!(growth.reuse_evictions, 1);
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 1));
        assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
        let modified = fs::metadata(path).unwrap().modified().unwrap();
        let replacement = root.join("replacement");
        fs::write(&replacement, &grown).unwrap();
        fs::File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        fs::rename(replacement, path).unwrap();
        let replaced = page(&root, &paths, &cache);
        assert_eq!(replaced.reuse_misses, 1, "inode alone invalidates");
        assert_eq!(replaced.reuse_evictions, 1);
        assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
        fs::write(path, b"{incomplete").unwrap();
        for attempt in 0..2 {
            let refused = page(&root, &paths, &cache);
            assert!(!refused.complete);
            assert_eq!(refused.refused.len(), 1);
            assert_eq!(refused.reuse_misses, 1);
            assert_eq!(refused.reuse_hits, 1);
            assert_eq!(refused.reuse_evictions, usize::from(attempt == 0));
            assert!(cache
                .with_cursor(|cursor| cursor.headers.get(paths.first().unwrap()))
                .unwrap()
                .is_none());
        }
        fs::write(path, original).unwrap();
        assert_eq!(page(&root, &paths, &cache).reuse_misses, 1);
        assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
        fs::remove_file(path).unwrap();
        let missing = page(&root, &paths, &cache);
        assert!(!missing.complete, "unreadable is not a hit");
        assert_eq!(missing.reuse_evictions, 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn byte_admission_refuses_optional_facts_and_clear_releases_them() {
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = sampled_scan::SharedCache::default();
        let refused =
            sampled_scan::codex_cursor::with_test_state_budget(0, || page(&root, &paths, &cache));
        assert!(
            refused.complete,
            "cache refusal never refuses the inventory"
        );
        assert_eq!(facts(&refused), facts(&fixture));
        assert!(cache
            .with_cursor(|cursor| cursor.headers.is_empty())
            .unwrap());
        let populated = page(&root, &paths, &cache);
        assert_eq!(populated.reuse_misses, paths.len());
        assert_eq!(page(&root, &paths, &cache).read_bytes, 0);
        cache.clear();
        assert!(cache
            .with_cursor(|cursor| cursor.headers.is_empty())
            .unwrap());
        READ_CALLS.with(|calls| calls.set(0));
        let cleared = page(&root, &paths, &cache);
        assert_eq!(cleared.reuse_misses, paths.len());
        assert_eq!(cleared.reuse_evictions, paths.len());
        READ_CALLS.with(|calls| assert_eq!(calls.get(), paths.len()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cache_population_is_capped_and_roster_removal_evicts() {
        let (root, fixture) = tests::fixture();
        let mut paths = paths(&fixture);
        let cache = sampled_scan::SharedCache::default();
        page(&root, &paths, &cache);
        cache
            .with_cursor(|cursor| {
                let facts = cursor.headers.get(paths.first().unwrap()).unwrap();
                for number in 0..=MAX_HEADER_FILES {
                    cursor
                        .headers
                        .refresh(format!("fake-{number}"), Some(facts.clone()));
                }
                assert_eq!(cursor.headers.entries.len(), MAX_HEADER_FILES);
                assert_charge(&cursor.headers);
            })
            .unwrap();
        let removed = paths.pop_last().unwrap();
        let next = page(&root, &paths, &cache);
        assert_eq!(next.reuse_hits, 1);
        assert_eq!(next.reuse_evictions, MAX_HEADER_FILES - 1);
        cache
            .with_cursor(|cursor| {
                assert_eq!(cursor.headers.entries.len(), 1);
                assert!(cursor.headers.get(&removed).is_none());
                assert_charge(&cursor.headers);
            })
            .unwrap();
        let empty = page(&root, &BTreeSet::new(), &cache);
        assert_eq!(empty.reuse_evictions, 1);
        cache
            .with_cursor(|cursor| {
                assert!(cursor.headers.entries.is_empty());
                assert_charge(&cursor.headers);
            })
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn ctime_only_reuses_but_nanosecond_mtime_and_symlink_do_not() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = sampled_scan::SharedCache::default();
        page(&root, &paths, &cache);
        let path = Path::new(paths.first().unwrap());
        let stat = fs::metadata(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let unchanged = page(&root, &paths, &cache);
        assert_eq!(unchanged.read_bytes, 0);
        // A refreshed ctime witness also avoids validation's fallback read.
        READ_CALLS.with(|calls| calls.set(0));
        unchanged
            .validate_membership(&fixture.headers[0].owner, &root)
            .unwrap();
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        let modified = stat.modified().unwrap() + std::time::Duration::from_nanos(1);
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(page(&root, &paths, &cache).reuse_misses, 1);
        let moved = root.join("moved");
        fs::rename(path, &moved).unwrap();
        symlink(&moved, path).unwrap();
        let refused = page(&root, &paths, &cache);
        assert!(!refused.complete);
        assert_eq!(refused.refused.len(), 1);
        assert_eq!(refused.reuse_hits, 1);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, unix))]
#[path = "codex_file_join/header_cache_output_tests.rs"]
mod header_cache_output_tests;
