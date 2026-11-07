//! Local proof for joining physical Codex rollouts. Requested-tier selectors
//! retain the existing reader's meaning; response ownership is a separate fact.
use super::*;
use crate::transcript_acquisition::FileStamp;

mod custody;
mod group_job;
mod independent_fold;
pub(super) use custody::{fan_out_body_witnesses, fan_out_offered_to_aliases};
pub(super) use group_job::{
    disclose_members, disclose_strict, end_group, group_counting_is_v2, job_key, rearm_unsettled,
    refusal_disclosure, refuse_independent, step_group, take_charge, Boot, EndInputs, GroupBoot,
    GroupEnd, GroupJob, GroupStep, JobInputs, StepInputs,
};
pub(super) use independent_fold::fold as fold_independent;

pub(super) const MAX_HEADER_BYTES: usize = 64 * 1024;

const DIRECTORY_CENSUS_UNPROVED: &str = "Codex joining directory census is unproved";
const DIRECTORY_MEMBERSHIP_CHANGED: &str = "Codex joining directory membership changed";
const HEADER_INVENTORY_INCOMPLETE: &str = "Codex joining header inventory is incomplete";
const ROOT_UNPROVED: &str = "Codex joining root is unproved";
const HEADER_STAT_FAILED: &str = "Codex joining header stat failed";
const HEADER_REREAD_FAILED: &str = "Codex joining header re-read failed";
const HEADER_OWNERSHIP_CHANGED: &str = "Codex joining header ownership changed";
const JOINED_MEMBER_OPEN_FAILED: &str = "Codex joined member open failed";
const JOINED_MEMBER_CHANGED: &str = "Codex joined member changed after replay";
/// Every fixed phrase a join validation failure carries, so `safe_error`
/// names the failed check instead of the bare "sync failed".
pub(crate) const CODEX_JOIN_VALIDATION_FAILURES: [&str; 9] = [
    DIRECTORY_CENSUS_UNPROVED,
    DIRECTORY_MEMBERSHIP_CHANGED,
    HEADER_INVENTORY_INCOMPLETE,
    ROOT_UNPROVED,
    HEADER_STAT_FAILED,
    HEADER_REREAD_FAILED,
    HEADER_OWNERSHIP_CHANGED,
    JOINED_MEMBER_OPEN_FAILED,
    JOINED_MEMBER_CHANGED,
];

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
type DirectoryListing = (BTreeSet<String>, Vec<(PathBuf, fs::Metadata)>, Vec<PathBuf>);

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
    /// Adopt the witness from a successful `relist`; checkpoint callers only
    /// inspect that proof and leave the frozen census unchanged.
    pub(super) fn refresh(&mut self, path: &Path, before: &fs::Metadata) {
        self.directories
            .insert(local_index_key(path), metadata_witness(before));
    }
    /// Drop a directory that no longer exists, with every census directory
    /// beneath it. A fresh walk would not list them either.
    pub(super) fn retire(&mut self, path: &Path) {
        self.directories
            .retain(|directory, _| !Path::new(directory).starts_with(path));
    }
    /// Stable listing shared by roster refresh and boundary validation.
    /// A missing directory is distinct from an unreadable or unstable listing.
    pub(super) fn relist(
        &self,
        directory: &Path,
        paths: &BTreeSet<String>,
    ) -> Result<Option<(fs::Metadata, DirectoryListing)>> {
        let before = match fs::symlink_metadata(directory) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            before.is_dir() && !before.file_type().is_symlink(),
            DIRECTORY_MEMBERSHIP_CHANGED
        );
        let mut present = BTreeSet::new();
        let mut appeared = Vec::new();
        let mut new_directories = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let path = entry.path();
            anyhow::ensure!(!kind.is_symlink(), DIRECTORY_MEMBERSHIP_CHANGED);
            if kind.is_dir() {
                if !self.contains(&path) {
                    new_directories.push(path);
                }
            } else if kind.is_file() && transcript_path_admitted(SnapshotSource::Codex, &path) {
                let key = local_index_key(&path);
                if !paths.contains(&key) {
                    let stat = fs::symlink_metadata(&path)?;
                    anyhow::ensure!(stat.is_file(), DIRECTORY_MEMBERSHIP_CHANGED);
                    appeared.push((path, stat));
                }
                present.insert(key);
            }
        }
        let after = fs::symlink_metadata(directory)?;
        anyhow::ensure!(
            after.is_dir()
                && !after.file_type().is_symlink()
                && metadata_witness(&after) == metadata_witness(&before),
            DIRECTORY_MEMBERSHIP_CHANGED
        );
        Ok(Some((before, (present, appeared, new_directories))))
    }
}

#[derive(Clone, Debug)]
pub(super) struct HeaderWitness {
    pub(super) candidate: CandidateFile,
    pub(super) owner: String,
    pub(super) home: PathBuf,
    pub(super) created_unix_ms: Option<i64>,
    metadata: String,
    stamp: crate::transcript_acquisition::FileStamp,
}
/// A header-pass candidate from its discovery stat. Opening the file later
/// refreshes size, mtime and identity from the opened object.
pub(super) fn header_candidate(
    scan_root: PathBuf,
    path: PathBuf,
    stat: &fs::Metadata,
) -> CandidateFile {
    CandidateFile {
        physical_identity: None,
        scan_root,
        path,
        size_bytes: stat.len(),
        modified_unix_seconds: stat.modified().ok().and_then(unix_seconds).unwrap_or(0),
        modified_unix_nanos: stat.modified().ok().and_then(unix_nanos).unwrap_or(0),
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    }
}
pub(super) fn member_home(root: &Path) -> PathBuf {
    root.ancestors()
        .find(|path| {
            matches!(
                path.file_name().and_then(|value| value.to_str()),
                Some("sessions" | "archived_sessions")
            )
        })
        .and_then(Path::parent)
        .unwrap_or(root)
        .to_path_buf()
}
// One bounded secure acquisition path; semantic inventory and sampled-scope
// witnesses both use it. Only inventory performs native header decoding.
fn read_header_bytes(
    candidate: &CandidateFile,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
    read_work: &mut usize,
) -> Result<(Vec<u8>, String, usize, FileStamp)> {
    let file = open_candidate_beneath_root(candidate)?;
    let before = file.metadata()?;
    anyhow::ensure!(before.is_file(), "Codex header is not a regular file");
    let stamp = FileStamp::capture(before.clone())?;
    let input = OpenedInput::encoded(file, &candidate.path, cache)?.header_only();
    let mut reader = BufReader::with_capacity(1024, input.take((MAX_HEADER_BYTES + 1) as u64));
    #[cfg(all(test, unix))]
    header_cache_tests::READ_CALLS.with(|calls| calls.set(calls.get() + 1));
    // Once reading begins, a failed attempt may have consumed the whole
    // recognition prefix. A funding refusal above consumes no header bytes.
    *read_work = MAX_HEADER_BYTES + 1;
    let acquired = (|| -> Result<_> {
        let bytes =
            read_header_line(&mut reader)?.context("Codex header exceeds its read bound")?;
        *read_work = (MAX_HEADER_BYTES + 1) - reader.get_ref().limit() as usize;
        let after = reader.get_ref().get_ref().get_ref().metadata()?;
        let witness = metadata_witness(&before);
        anyhow::ensure!(
            stamp.same_content(&FileStamp::capture(after.clone())?)
                && metadata_witness(&after) == witness,
            HEADER_CHANGED_WHILE_READ
        );
        Ok((bytes, witness, *read_work, stamp))
    })();
    reader.into_inner().into_inner().close();
    acquired
}
pub(super) fn owning_header(value: &Value) -> Result<(String, Option<i64>)> {
    let meta =
        codex_session_meta_payload(value).context("Codex first record is not a owning header")?;
    let owner = resolve_codex_identity_option(codex_identity_at(meta, &["id"]))
        .context("Codex header lacks ownership")?;
    let created_unix_ms = meta
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .and_then(|created| i64::try_from(created.unix_timestamp_nanos() / 1_000_000).ok());
    Ok((owner, created_unix_ms))
}

pub(super) fn read_header_line(input: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    input
        .take((MAX_HEADER_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    Ok((bytes.len() <= MAX_HEADER_BYTES && bytes.last() == Some(&b'\n')).then_some(bytes))
}

type ReadHeader = (CachedHeader, String);
fn read_header(
    candidate: &CandidateFile,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
    read_work: &mut usize,
) -> Result<ReadHeader> {
    let (bytes, witness, read_bytes, stamp) = read_header_bytes(candidate, cache, read_work)?;
    #[cfg(test)]
    codex_zst_refusal_tests::jsonl_parse_attempted();
    let value: Value = serde_json::from_slice(&bytes)?;
    let (owner, created_unix_ms) = owning_header(&value)?;
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
fn read_header_settled(
    candidate: &CandidateFile,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
) -> (Result<ReadHeader>, usize) {
    let mut retried = 0;
    let mut total_work = 0usize;
    loop {
        let mut read_work = 0;
        let result = read_header(candidate, cache, &mut read_work);
        total_work = total_work.saturating_add(read_work);
        match result {
            Err(error)
                if retried + 1 < HEADER_READ_ATTEMPTS
                    && error.to_string() == HEADER_CHANGED_WHILE_READ =>
            {
                retried += 1
            }
            result => return (result, total_work),
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
/// The session id the file's owning header names now: the lineage a stored
/// Tail head continues (D131), read as the inventory reads it.
#[cfg(unix)]
pub(super) fn header_owner(candidate: &CandidateFile) -> Result<String> {
    read_header_settled(candidate, None)
        .0
        .map(|(header, _)| header.owner)
}
/// Raw header digest for a file whose owning header the native inventory has
/// already established. No extra decoded Value is retained or allocated.
pub(super) fn header_reduction_witness(candidate: &CandidateFile) -> Result<String> {
    refuse_compressed_codex(Some(&candidate.path), None, CodexZstCause::HeaderUnfunded)?;
    read_header_bytes(candidate, None, &mut 0)
        .map(|(bytes, _, _, _)| format!("{:x}", Sha256::digest(bytes)))
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
            let keep = paths
                .binary_search_by(|path| path.as_os_str().cmp(Path::new(key).as_os_str()))
                .is_ok();
            if !keep {
                *evictions = evictions.saturating_add(1);
                *heap_bytes = heap_bytes.saturating_sub(Self::entry_heap(key.capacity(), header));
            }
            keep
        });
    }
    #[cfg(test)]
    pub(in crate::snapshots) fn clear(&mut self) {
        self.evictions = self.evictions.saturating_add(self.entries.len());
        self.entries.clear();
        self.heap_bytes = 0;
    }
    fn take_evictions(&mut self) -> usize {
        std::mem::take(&mut self.evictions)
    }
    #[cfg(test)]
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
        self.entries.get(key).cloned()
    }
    pub(in crate::snapshots) fn refresh(&mut self, key: String, header: Option<CachedHeader>) {
        if let Some((key, old)) = self.entries.remove_entry(&key) {
            self.evictions = self.evictions.saturating_add(1);
            self.heap_bytes = self
                .heap_bytes
                .saturating_sub(Self::entry_heap(key.capacity(), &old));
        }
        if let Some(header) = header {
            self.heap_bytes = self
                .heap_bytes
                .saturating_add(Self::entry_heap(key.capacity(), &header));
            self.entries.insert(key, header);
        }
    }
    fn entry_heap(key_capacity: usize, header: &CachedHeader) -> usize {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        let mut c = Counter::new(usize::MAX);
        c.add(key_capacity)
            .and_then(|()| header.heap_bound(&mut c))
            .map_or(usize::MAX, |()| c.bytes)
    }
    /// The header facts' own resident bytes (tests).
    #[cfg(test)]
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
    pub(super) pending: VecDeque<PathBuf>,
    pub(super) headers: Vec<HeaderWitness>,
    pub(super) directories: DirectoryCensus,
    pub(super) complete: bool,
    pub(super) held_owners: BTreeSet<String>,
    pub(super) read_bytes: usize,
    pub(super) reuse_hits: usize,
    pub(super) reuse_misses: usize,
    pub(super) bytes_avoided: usize,
    pub(super) reuse_evictions: usize,
    cache_pruned: bool,
    /// Roster files whose first record was refused, each with the metadata
    /// witness seen at the refusal (`None` when it could not be read). This is
    /// the evidence a held page waits on; see `CodexInventoryHold`.
    pub(super) refused: BTreeMap<String, Option<String>>,
    /// File-level diagnostics use the existing sampled cause inventory.
    pub(super) unreadable_causes: crate::codex_scan_diagnostics::UnreadableCauses,
}

/// A group's key in `HeaderInventory::groups`, which is also the order the
/// inventory reads groups in.
fn group_key(home: &Path, owner: &str) -> String {
    sha256_hex(&["codex_file_group:v1", &local_index_key(home), owner])
}

/// Exact plaintext siblings own the ordinary roster before either header opens.
/// Selection uses this same predicate with the complete discovered path set.
pub(super) fn shadowed_compressed_path(path: &Path, paths: &BTreeSet<String>) -> bool {
    is_compressed_codex_rollout(Some(path), None)
        && paths.contains(&local_index_key(&path.with_extension("")))
}

/// The archive Codex wrote in place of a plaintext rollout that vanished
/// between the roster and its open: the sibling `shadowed_compressed_path`
/// kept out of the roster, a regular file in the same directory. It is read
/// under the same open and header gates and refused under its own path.
fn swapped_archive_sibling(error: &anyhow::Error, path: &Path) -> Option<PathBuf> {
    let not_found = |error: &std::io::Error| error.kind() == std::io::ErrorKind::NotFound;
    let archive = path.with_extension("jsonl.zst");
    (error
        .downcast_ref::<std::io::Error>()
        .is_some_and(not_found)
        && path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
        && fs::symlink_metadata(path).is_err_and(|error| not_found(&error))
        && fs::symlink_metadata(&archive)
            .is_ok_and(|stat| stat.is_file() && !stat.file_type().is_symlink()))
    .then_some(archive)
}

impl HeaderInventory {
    pub(super) fn new(
        roots: &[PathBuf],
        paths: &BTreeSet<String>,
        directories: Option<&DirectoryCensus>,
    ) -> Self {
        Self {
            roots: roots.to_vec(),
            pending: paths
                .iter()
                .filter(|path| !shadowed_compressed_path(Path::new(path), paths))
                .map(PathBuf::from)
                .collect(),
            headers: Vec::new(),
            held_owners: group_job::unsealed_owners(paths),
            directories: directories.cloned().unwrap_or_default(),
            complete: directories.is_some_and(|value| value.stable),
            read_bytes: 0,
            reuse_hits: 0,
            reuse_misses: 0,
            bytes_avoided: 0,
            reuse_evictions: 0,
            cache_pruned: false,
            refused: BTreeMap::new(),
            unreadable_causes: Default::default(),
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
    /// What a continuation page reads: the headers `keep` names, in path
    /// order, and completeness. The directory census goes too: only an
    /// ordinary page's coverage and membership checks read it.
    pub(super) fn keep_job_share(&mut self, keep: impl Fn(&HeaderWitness) -> bool) {
        self.headers.retain(keep);
        self.headers.shrink_to_fit();
        self.pending.shrink_to_fit();
        self.directories = DirectoryCensus::default();
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
        self.step_encoded(metadata, None)
    }
    /// Funded ordinary header inventory, independent of the body's encoding.
    #[cfg(test)]
    pub(super) fn step_encoded(
        &mut self,
        metadata: &CodexTitleMetadata,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
    ) -> bool {
        self.step_selected(metadata, &mut ScanIndex::default(), &BTreeMap::new(), cache)
    }
    pub(super) fn step_selected(
        &mut self,
        metadata: &CodexTitleMetadata,
        index: &mut ScanIndex,
        flags: &BTreeMap<String, (bool, bool)>,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
    ) -> bool {
        let funded_cache = cache;
        let cache = cache.map(Arc::as_ref);
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
        let Some(path) = self.pending.pop_front() else {
            return true;
        };
        if codex_session_id_candidates_from_path(&path)
            .iter()
            .any(|owner| self.held_owners.contains(owner))
        {
            return false;
        }
        let Some(scan_root) = self.scan_root(&path) else {
            self.complete = false;
            self.refused
                .insert(local_index_key(&path), path_witness(&path));
            self.unreadable_causes.record_sampled(
                UnreadableCause::ScopeObject,
                1,
                Some((&path, &local_index_key(&path))),
            );
            return false;
        };
        // 11b-0b composition: skip a currently held file BEFORE any header
        // lookup. Reuse only owner/time/stamp/read-count facts; rebuild custody
        // cause, owner fences, completeness, membership and exclusions each pass.
        // The second landing must preserve 11b's early skip and test warm -> held.
        let key = local_index_key(&path);
        self.reuse_misses += 1;
        let mut retry_candidate = None;
        let result = (|| -> Result<HeaderWitness> {
            let stat = fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                stat.is_file() && !stat.file_type().is_symlink(),
                "invalid Codex header member"
            );
            let mut candidate = header_candidate(scan_root, path, &stat);
            prepare_owned_scan_candidate(
                SnapshotSource::Codex,
                &mut candidate,
                metadata,
                &ClaudeTitleMetadata::default(),
                None,
            );
            retry_candidate = Some(candidate.clone());
            let current = open_candidate_beneath_root(&candidate)?.metadata()?;
            let stamp = FileStamp::capture(current.clone())?;
            // One securely acquired physical witness for both durable and RAM facts.
            let joined_archive = if codex_archive_path(&candidate.path)
                && index.files.get(&key).is_some_and(|entry| {
                    entry.codex_joined_member_set.is_some()
                        && codex_index_file_body_accepted(index, &key, entry)
                }) {
                state_v2::load_head(index, &key, 1)?
                    .filter(|head| {
                        head.common
                            .inventory
                            .as_ref()
                            .is_some_and(|facts| facts.stamp.matches_acquisition(&stamp))
                    })
                    .and_then(|head| {
                        let facts = head.common.inventory?;
                        Some(CachedHeader {
                            stamp: stamp.clone(),
                            owner: facts.owner,
                            created_unix_ms: facts.created_unix_ms,
                            read_bytes: usize::try_from(facts.read_bytes).unwrap_or(usize::MAX),
                        })
                    })
            } else {
                None
            };
            let durable = joined_archive.or(index
                .codex_physical_matches(&key, &current)?
                .filter(|(matched, _)| *matched)
                .and_then(|(_, head)| {
                    let facts = head.common.inventory.as_ref();
                    let owner = facts.map(|facts| facts.owner.clone()).or_else(|| {
                        tail_source::codex::header_facts(head.revision, &head.body)
                            .ok()?
                            .1
                    })?;
                    Some(CachedHeader {
                        stamp: stamp.clone(),
                        owner,
                        created_unix_ms: facts.and_then(|facts| facts.created_unix_ms),
                        read_bytes: facts.map_or(0, |facts| {
                            usize::try_from(facts.read_bytes).unwrap_or(usize::MAX)
                        }),
                    })
                }));
            let reused = durable
                .or_else(|| {
                    let cached = cache?
                        .with_cursor(|cursor| cursor.headers.get(&key))
                        .flatten()?;
                    (cached.stamp.same_object(&stamp) && cached.stamp.same_content(&stamp))
                        .then_some(cached)
                })
                .map(|facts| {
                    self.reuse_hits += 1;
                    self.reuse_misses -= 1;
                    self.bytes_avoided = self.bytes_avoided.saturating_add(facts.read_bytes);
                    (facts, metadata_witness(&current))
                });
            let (facts, witness) = match reused {
                Some(header) => header,
                None => {
                    if let Some(cache) = cache {
                        cache.refresh_header(key.clone(), None);
                    }
                    let (header, read_work) = read_header_settled(&candidate, funded_cache);
                    self.read_bytes = self.read_bytes.saturating_add(read_work);
                    let (facts, witness) = header?;
                    if let Some(cache) = cache {
                        cache.refresh_header(key.clone(), Some(facts.clone()));
                    }
                    (facts, witness)
                }
            };
            Ok(HeaderWitness {
                home: member_home(&candidate.scan_root),
                candidate,
                owner: facts.owner,
                created_unix_ms: facts.created_unix_ms,
                metadata: witness,
                stamp: facts.stamp,
            })
        })();
        match result {
            Ok(header) => {
                self.headers.push(header);
            }
            Err(error) => {
                if retry_candidate.as_ref().is_some_and(|candidate| {
                    sampled_scan::codex_cursor::requeue_refused(
                        SnapshotSource::Codex,
                        &error,
                        index,
                        flags,
                        candidate,
                    )
                }) {
                    // Funding uncertainty holds filename dependants only. An
                    // unknown filename retains the existing wildcard fence.
                    let owners = codex_session_id_candidates_from_path(Path::new(&key));
                    self.complete &= codex_archive_path(Path::new(&key)) && !owners.is_empty();
                    self.held_owners.extend(owners);
                    return false;
                }
                if let Some(cache) = cache {
                    cache.refresh_header(key.clone(), None);
                }
                if let Some(archive) = swapped_archive_sibling(&error, Path::new(&key)) {
                    // Pending keeps its whole-string path order (see
                    // `owner_for_path`), so headers stay sorted.
                    if let Err(at) = self
                        .pending
                        .binary_search_by(|pending| pending.as_os_str().cmp(archive.as_os_str()))
                    {
                        self.pending.insert(at, archive);
                    }
                    return false;
                }
                self.complete = false;
                let cause = if error.downcast_ref::<std::io::Error>().is_some() {
                    UnreadableCause::OpenRead
                } else {
                    UnreadableCause::AliasParser
                };
                self.unreadable_causes
                    .record_sampled(cause, 1, Some((Path::new(&key), &key)));
                let witness = path_witness(Path::new(&key));
                self.refused.insert(key, witness);
            }
        }
        false
    }
    pub(super) fn groups(&self) -> BTreeMap<String, Group> {
        let mut groups = BTreeMap::<String, Group>::new();
        for header in &self.headers {
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
        // Ordinary replacement/carry archives retain main's singleton path.
        // Revert groups alone acquire their compressed independent members.
        for group in groups.values_mut() {
            if !group_job::independent_group(group) {
                group
                    .members
                    .retain(|member| !codex_archive_path(&member.path));
            }
        }
        groups.retain(|_, group| !group.members.is_empty());
        groups
    }
    /// Header uncertainty remains a wildcard; complete current headers name
    /// only the owners whose cross-home membership conflicts.
    pub(super) fn affected_owners(&self) -> Option<BTreeSet<String>> {
        if !self.complete || !self.pending.is_empty() {
            return None;
        }
        let mut affected = self.held_owners.clone();
        let mut homes = BTreeMap::new();
        for header in &self.headers {
            if homes
                .insert(&header.owner, &header.home)
                .is_some_and(|home| home != &header.home)
            {
                affected.insert(header.owner.clone());
            }
        }
        Some(affected)
    }
    pub(super) fn membership_complete(
        &self,
        owner: &str,
        affected: Option<&BTreeSet<String>>,
    ) -> bool {
        self.complete
            && self.pending.is_empty()
            && affected.is_some_and(|affected| !affected.contains(owner))
    }
    fn scan_root(&self, path: &Path) -> Option<PathBuf> {
        self.roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
    }
    fn validate_memberships(
        &self,
        owners: &BTreeSet<String>,
        paths: &BTreeSet<String>,
    ) -> Result<usize> {
        if owners.is_empty() {
            return Ok(0);
        }
        let affected = self
            .affected_owners()
            .context(HEADER_INVENTORY_INCOMPLETE)?;
        anyhow::ensure!(
            owners
                .iter()
                .all(|owner| self.membership_complete(owner, Some(&affected))),
            HEADER_INVENTORY_INCOMPLETE
        );
        for root in &self.roots {
            anyhow::ensure!(self.directories.contains(root), ROOT_UNPROVED);
        }
        anyhow::ensure!(self.directories.stable, DIRECTORY_CENSUS_UNPROVED);
        let mut directories = VecDeque::from(self.directories.moved_directories());
        while let Some(directory) = directories.pop_front() {
            let (_, (_, appeared, new_directories)) = self
                .directories
                .relist(&directory, paths)
                .context(DIRECTORY_MEMBERSHIP_CHANGED)?
                .context(DIRECTORY_MEMBERSHIP_CHANGED)?;
            // Inspect new date trees without advancing the frozen census.
            // The next roster refresh queues them for the bounded walk.
            directories.extend(new_directories);
            for (path, stat) in appeared {
                anyhow::ensure!(
                    self.new_member_owners(&path, &stat, paths)?
                        .is_disjoint(owners),
                    DIRECTORY_MEMBERSHIP_CHANGED
                );
            }
        }
        for header in &self.headers {
            let stat = match fs::symlink_metadata(&header.candidate.path) {
                Ok(stat) => stat,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && !owners.contains(&header.owner) =>
                {
                    // Losing unrelated plaintext can activate its roster archive.
                    // Reuse the new-archive filename fence; never decode here.
                    let archive = header.candidate.path.with_extension("jsonl.zst");
                    if !codex_archive_path(&header.candidate.path) {
                        match fs::symlink_metadata(&archive) {
                            Ok(stat) => {
                                anyhow::ensure!(
                                    self.new_member_owners(&archive, &stat, paths)?
                                        .is_disjoint(owners),
                                    DIRECTORY_MEMBERSHIP_CHANGED
                                );
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error).context(HEADER_STAT_FAILED),
                        }
                    }
                    continue;
                }
                Err(error) => return Err(error).context(HEADER_STAT_FAILED),
            };
            if metadata_witness(&stat) == header.metadata {
                continue;
            }
            let (current, _) = read_header_settled(&header.candidate, None)
                .0
                .context(HEADER_REREAD_FAILED)?;
            anyhow::ensure!(current.owner == header.owner, HEADER_OWNERSHIP_CHANGED);
        }
        Ok(self.headers.len())
    }
    fn new_member_owners(
        &self,
        path: &Path,
        stat: &fs::Metadata,
        paths: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>> {
        if codex_archive_path(path) {
            if shadowed_compressed_path(path, paths)
                && fs::symlink_metadata(path.with_extension(""))
                    .is_ok_and(|stat| stat.is_file() && !stat.file_type().is_symlink())
            {
                return Ok(BTreeSet::new());
            }
            let names = codex_session_id_candidates_from_path(path);
            anyhow::ensure!(!names.is_empty(), HEADER_REREAD_FAILED);
            return Ok(names.into_iter().collect());
        }
        let root = self.scan_root(path).context(ROOT_UNPROVED)?;
        let (current, _) =
            read_header_settled(&header_candidate(root, path.to_path_buf(), stat), None)
                .0
                .context(HEADER_REREAD_FAILED)?;
        Ok(BTreeSet::from([current.owner]))
    }
}
crate::heap_layout_bound::fields!(DirectoryCensus; directories, stable);
crate::heap_layout_bound::fields!(HeaderWitness; candidate, owner, home, created_unix_ms, metadata, stamp);
crate::heap_layout_bound::fields!(HeaderInventory; roots, pending, headers, directories, complete, held_owners, read_bytes, reuse_hits, reuse_misses, bytes_avoided, reuse_evictions, cache_pruned, refused, unreadable_causes);

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
    owners: BTreeSet<String>,
    paths: Arc<BTreeSet<String>>,
}
impl Validation {
    /// Joined groups retain their member certificates. Every surviving
    /// singleton registers its owner in the same boundary validation scope.
    pub(super) fn new(
        inventory: HeaderInventory,
        groups: Vec<Group>,
        owners: &BTreeSet<String>,
        paths: BTreeSet<String>,
    ) -> Self {
        let owners = owners
            .iter()
            .cloned()
            .chain(groups.iter().map(|group| group.owner.clone()))
            .collect();
        Self {
            inventory,
            groups,
            owners,
            paths: Arc::new(paths),
        }
    }
    pub(super) fn validate_all(&self) -> Result<usize> {
        self.validate(&self.owners)
    }
    pub(super) fn validate(&self, owners: &BTreeSet<String>) -> Result<usize> {
        let selected = self
            .owners
            .intersection(owners)
            .cloned()
            .collect::<BTreeSet<_>>();
        let checked_headers = self
            .inventory
            .validate_memberships(&selected, &self.paths)?;
        for group in self
            .groups
            .iter()
            .filter(|group| owners.contains(&group.owner))
        {
            for member in &group.members {
                let mut opened = member.clone();
                let file = open_candidate_file(SnapshotSource::Codex, &mut opened)
                    .context(JOINED_MEMBER_OPEN_FAILED)?;
                let granted = group.live.as_ref().is_some_and(|(key, prefix)| {
                    *key == local_index_key(&member.path) && prefix.holds(&file)
                });
                anyhow::ensure!(
                    granted || opened.opened_object_identity == member.opened_object_identity,
                    JOINED_MEMBER_CHANGED
                );
            }
        }
        Ok(checked_headers)
    }
    /// Existing group-hold rollback also removes singleton publication owners.
    /// Keep the full inventory: other-home dependencies still constrain survivors.
    pub(super) fn remove_owners(&mut self, held: &BTreeSet<String>) {
        self.owners.retain(|owner| !held.contains(owner));
        self.groups.retain(|group| !held.contains(&group.owner));
    }
}
crate::heap_layout_bound::fields!(Group; owner, home, members, live);
crate::heap_layout_bound::fields!(Validation; inventory, groups, owners, paths);

/// Reuse existing per-file inventory facts for settled archive members. This
/// stages no reduction, delivery credit or admitted-key projection.
pub(super) fn stage_independent_inventory(
    index: &ScanIndex,
    members: &[CandidateFile],
    owner: &str,
) -> Result<()> {
    let Some(route) = state_v2::runtime_path(index)? else {
        return Ok(());
    };
    let mut observations = Vec::new();
    for member in members {
        let key = local_index_key(&member.path);
        let file = open_candidate_beneath_root(member)?;
        let stamp = sampled_scan::codex_cursor::OpenStamp::capture(&file)?.content_stamp();
        let prior = state_v2::load_head(index, &key, 1)?;
        let (representation, summary) = prior.map_or(
            (
                state_v2::Representation::Archive,
                state_v2::DebtSummary::default(),
            ),
            |prior| (prior.common.representation, prior.common.debt),
        );
        let observation = state_v2::Observation {
            representation,
            summary,
            inventory: Some(state_v2::InventoryFacts {
                owner: owner.to_owned(),
                created_unix_ms: None,
                read_bytes: MAX_HEADER_BYTES as u64,
                stamp,
            }),
            ..state_v2::Observation::default()
        };
        observations.push((key, observation));
    }
    state_v2::observe_tails(&route, observations)
}

pub(super) fn captured_join(witness: &str) -> String {
    format!("codex_captured_join:v1:{witness}")
}
pub(super) fn valid_captured_join(value: &str) -> bool {
    value
        .strip_prefix("codex_captured_join:v1:")
        .is_some_and(valid_codex_protected_owner)
}
pub(super) fn member_set_witness(members: &[CandidateFile]) -> String {
    member_set_witness_of(members.iter().map(|member| {
        (
            local_index_key(&member.path),
            member.source_file_fingerprint.as_str(),
        )
    }))
}
/// The same digest over (index key, source revision) pairs, as the saved
/// member entries record them.
pub(super) fn member_set_witness_of<'a>(
    members: impl IntoIterator<Item = (String, &'a str)>,
) -> String {
    let sorted = members.into_iter().collect::<BTreeMap<_, _>>();
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
/// Previous application evidence, not provider billing truth. Only hashes of
/// physical records/context and the applied priority provenance are retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedTierReceipt {
    version: u16,
    derivation: String,
    /// The delivery context it was written under, kept for older readers. Never
    /// compared: no setting or capability changes which tier a record carries.
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
    /// What a parse reads of this receipt: everything but the delivery context
    /// it was written under.
    pub(in crate::snapshots) fn parse_input(&self) -> String {
        serde_json::to_string(&Self {
            scope: String::new(),
            ..self.clone()
        })
        .unwrap_or_else(|_| "unserializable".to_owned())
    }
    pub(super) fn covered_by(&self, previous: &Self) -> bool {
        self.version == previous.version
            && self.derivation == previous.derivation
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
                || receipt.records == 0
                || !crate::hex::is_sha256_lower(&receipt.prefix_digest)
                || receipt.tiers.iter().any(|(key, source)| {
                    !crate::hex::is_sha256_lower(key)
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
        context.context.remove(CODEX_THREAD_TIER);
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
            if source.len() > 64 {
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
            "Codex applied-tier receipt is unavailable or invalid"
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
/// Named group refusals (§i). Every reason is terminal debt for the attempt
/// (outcome R): the members are disclosed as
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
    /// A `history_base.thread_id` names no member of this owner's group:
    /// typically a compressed (`.zst`, not yet scanned) predecessor, or
    /// another owner's file named without `forked_from_id`.
    MissingPredecessor,
}
impl JoinRefusal {
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
crate::heap_layout_bound::no_heap!(true; JoinRefusal);

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

/// One independent member's header placement: its raw creator pair. A revert
/// header with a positive ordinal and no fork id certifies no creator yet names
/// its account, so members fold only under one raw pair; a pair missing on one
/// member or a different pair holds the group. The pair only gates the fold and
/// never becomes creator evidence. A certified creator must name its own pair.
fn independent_member_placement(
    certified: Option<(String, String)>,
    raw: Option<(String, String)>,
) -> std::result::Result<Option<(String, String)>, JoinRefusal> {
    if certified.is_some_and(|certified| Some(&certified) != raw.as_ref()) {
        return Err(JoinRefusal::Overlap);
    }
    Ok(raw)
}

/// The group proof, fed inside the one native replay: the native side in
/// `TierReplay::observe`, the UI side by the parser admission tap (S10)
/// after actual admission. It moves from member to member with the replay.
/// Only compact identities, counters and per-member tuple balances are kept.
#[derive(Clone, Debug)]
pub(super) struct StreamProof {
    owner: String,
    v2: bool,
    independent: bool,
    independent_placement: Option<Option<(String, String)>>,
    independent_classification: Option<(Option<String>, Option<String>)>,
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

/// Heap bytes of a std B-tree of `len` inline entries. Every
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
        self.independent_placement.heap_bound(c)?;
        self.independent_classification.heap_bound(c)?;
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
            independent: false,
            independent_placement: None,
            independent_classification: None,
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

    fn independent(owner: String, members: usize) -> Self {
        let mut proof = Self::new(owner, false, vec![MemberPlan::default(); members]);
        proof.independent = true;
        proof
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
                if self.independent {
                    if meta.get("forked_from_id").is_some_and(|v| !v.is_null())
                        || meta
                            .get("subagent_history_start_ordinal")
                            .is_some_and(|v| !v.is_null())
                        || string_eq_at(meta, &["thread_source"], "agent_created_thread")
                    {
                        return Err(JoinRefusal::ForkedFromOtherSession);
                    }
                    let placement = independent_member_placement(
                        codex_creator_header_evidence(value, meta).and_then(|e| {
                            Some((e.account_identifier_hash?, e.provider_workspace_hash?))
                        }),
                        codex_raw_creator_pair(meta),
                    )?;
                    let classification = (
                        string_at(meta, &["thread_source"]),
                        meta.get("source").map(Value::to_string),
                    );
                    if self
                        .independent_placement
                        .as_ref()
                        .is_some_and(|prior| prior != &placement)
                        || self
                            .independent_classification
                            .as_ref()
                            .is_some_and(|prior| prior != &classification)
                    {
                        return Err(JoinRefusal::Overlap);
                    }
                    self.independent_placement = Some(placement);
                    self.independent_classification = Some(classification);
                }
            }
            None if first => return Err(JoinRefusal::Corrupt),
            None => {}
        }
        if self.independent {
            return Ok(());
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
        if self.independent {
            return if self.v2 {
                Err(JoinRefusal::V2UnboundUi)
            } else {
                Ok(())
            };
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
        if self.independent {
            return;
        }
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
            // The predecessor is outside the inventory.
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
crate::heap_layout_bound::no_heap!(false; Tokens);

#[cfg(test)]
pub(super) mod tests {
    use super::*;

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
            cache: None,
            index,
        })?;
        let no_scope = |_: &CandidateFile| None;
        let inputs = StepInputs {
            metadata: &metadata,
            attribution: None,
            live_scope: &no_scope,
            cache: None,
            collected_at: "2026-10-01T12:00:00Z",
            index,
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
    /// [regress] Failed carry proof constrains only its established owner.
    #[test]
    fn carry_deferral_holds_only_its_proven_owner() {
        let mut inventory = HeaderInventory::new(&[], &BTreeSet::new(), None);
        inventory.complete = true;
        inventory.held_owners.insert("held".into());
        let affected = inventory.affected_owners();
        assert!(!inventory.membership_complete("held", affected.as_ref()));
        assert!(inventory.membership_complete("independent", affected.as_ref()));
        inventory.complete = false;
        assert!(inventory.affected_owners().is_none());
    }

    #[test]
    fn header_inventory_completes_valid_large_headers_without_a_volume_limit() {
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
    fn ordinary_compressed_header_retains_pending_on_funding_refusal_and_plain_sibling_wins() {
        let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
        let (root, fixture) = fixture();
        let sessions = root.join("sessions");
        let plain = fixture.headers[0].candidate.path.clone();
        let compressed = plain.with_extension("jsonl.zst");
        fs::write(
            &compressed,
            zstd::stream::encode_all(&fs::read(&plain).unwrap()[..], 1).unwrap(),
        )
        .unwrap();
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let paths = BTreeSet::from([local_index_key(&plain), local_index_key(&compressed)]);
        let metadata = CodexTitleMetadata::default();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut inventory =
            HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
        while !inventory.step_encoded(&metadata, Some(&cache)) {}
        assert!(inventory.complete);
        assert_eq!(inventory.headers.len(), 1);
        assert_eq!(inventory.headers[0].candidate.path, plain);
        assert_eq!(inventory.owner_for_path(&compressed), None);

        let paths = BTreeSet::from([local_index_key(&compressed)]);
        let mut inventory =
            HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
        assert!(!inventory.step_encoded(&metadata, None));
        assert!(inventory.pending.is_empty());
        assert!(!inventory.complete);
        assert!(inventory.headers.is_empty());
        assert!(inventory.refused.is_empty());
        assert_eq!(inventory.read_bytes, 0);
        assert!(!inventory.content_unchanged());
        assert!(inventory.affected_owners().is_none());
        // A later ordinary attempt retries after funding returns.
        let mut inventory =
            HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
        while !inventory.step_encoded(&metadata, Some(&cache)) {}
        assert!(
            inventory.complete,
            "funded recognition: read={}, refusals={}, causes={}",
            inventory.read_bytes,
            inventory.refused.len(),
            serde_json::to_string(&inventory.unreadable_causes).unwrap()
        );
        assert_eq!(inventory.headers.len(), 1);
        assert_eq!(inventory.headers[0].owner, fixture.headers[0].owner);
        assert_eq!(inventory.headers[0].candidate.path, compressed);
        assert!(inventory.read_bytes > 0);
        assert!(cache
            .with_cursor(|cursor| cursor.headers.get(paths.first().unwrap()))
            .unwrap()
            .is_some());
        fs::remove_dir_all(root).unwrap();
    }

    /// [regress] Codex compressing a rollout after the roster listed both
    /// copies reads the shadowed archive instead of refusing the plaintext.
    #[cfg(unix)]
    #[test]
    fn header_inventory_reads_the_archive_codex_swapped_in_after_listing() {
        let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
        let metadata = CodexTitleMetadata::default();
        let swapped = |write_archive: &dyn Fn(&Path, &Path, &[u8])| {
            let (root, fixture) = fixture();
            let sessions = root.join("sessions");
            let plain = fixture.headers[0].candidate.path.clone();
            let archive = plain.with_extension("jsonl.zst");
            write_archive(&root, &archive, &fs::read(&plain).unwrap()[..]);
            let mut directories = DirectoryCensus::new();
            directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
            let paths = BTreeSet::from([local_index_key(&plain), local_index_key(&archive)]);
            let mut inventory =
                HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
            assert_eq!(
                inventory.pending,
                std::slice::from_ref(&plain),
                "the roster shadows the archive"
            );
            // Codex replaces the plaintext between the roster and its open.
            fs::remove_file(&plain).unwrap();
            let cache = Arc::new(sampled_scan::SharedCache::default());
            while !inventory.step_encoded(&metadata, Some(&cache)) {}
            let owner = fixture.headers[0].owner.clone();
            (root, plain, archive, owner, inventory)
        };
        let causes = |inventory: &HeaderInventory| {
            let causes = serde_json::to_value(inventory.unreadable_causes).unwrap();
            serde_json::from_value::<Vec<u64>>(causes["counts"].clone()).unwrap()
        };
        let refused =
            |inventory: &HeaderInventory| inventory.refused.keys().cloned().collect::<Vec<_>>();

        let (root, _, archive, owner, inventory) = swapped(&|_, archive, plain| {
            fs::write(archive, zstd::stream::encode_all(plain, 1).unwrap()).unwrap();
        });
        assert!(inventory.complete);
        assert!(inventory.refused.is_empty());
        assert_eq!(causes(&inventory), [0; 8]);
        assert_eq!(inventory.headers.len(), 1);
        assert_eq!(inventory.headers[0].candidate.path, archive);
        assert_eq!(inventory.owner_for_path(&archive), Some(owner.as_str()));
        fs::remove_dir_all(root).unwrap();

        // An unreadable archive is refused and counted under its own path.
        let (root, _, archive, _, inventory) = swapped(&|_, archive, _| {
            fs::write(archive, b"not a zstd frame").unwrap();
        });
        assert!(!inventory.complete);
        assert!(inventory.headers.is_empty());
        assert_eq!(refused(&inventory), [local_index_key(&archive)]);
        assert_eq!(causes(&inventory).iter().sum::<u64>(), 1);
        fs::remove_dir_all(root).unwrap();

        // No archive, or one that is a symlink (here to a file outside the
        // root): the plaintext stays refused as OpenRead, nothing else read.
        let symlink_out = |root: &Path, archive: &Path, plain: &[u8]| {
            let outside = root.join("outside.jsonl.zst");
            fs::write(&outside, zstd::stream::encode_all(plain, 1).unwrap()).unwrap();
            std::os::unix::fs::symlink(&outside, archive).unwrap();
        };
        let unchanged = |write_archive: &dyn Fn(&Path, &Path, &[u8])| {
            let (root, plain, _, _, inventory) = swapped(write_archive);
            assert!(!inventory.complete);
            assert!(inventory.headers.is_empty());
            assert_eq!(inventory.read_bytes, 0);
            assert_eq!(refused(&inventory), [local_index_key(&plain)]);
            let mut expected = [0; 8];
            expected[UnreadableCause::OpenRead as usize] = 1;
            assert_eq!(causes(&inventory), expected);
            fs::remove_dir_all(root).unwrap();
        };
        unchanged(&|_, _, _| {});
        unchanged(&symlink_out);
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
        let validation = validator(inventory);
        validation.validate_all().unwrap();
        fs::write(root.join("sessions/new.jsonl"), "new member").unwrap();
        assert!(validation.validate_all().is_err());
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
        assert!(validator(inventory).validate_all().is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn proven_body_failure_affects_only_its_owner_and_unknown_header_is_a_wildcard() {
        let (root, original) = fixture();
        let sessions = root.join("sessions");
        let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
        let failed = original.headers[0].candidate.path.clone();
        // A reachable body loss AFTER a valid owning header, with a same-id
        // sibling. No cached-header byte read is invented for this fixture.
        let mut body = fs::read(&failed).unwrap();
        body.extend_from_slice(b"\xff\n");
        fs::write(&failed, body).unwrap();
        let healthy_path = sessions.join("healthy.jsonl");
        fs::write(
            &healthy_path,
            member(healthy, "healthy", 100, 100)
                .iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let paths = original
            .headers
            .iter()
            .map(|header| local_index_key(&header.candidate.path))
            .chain(std::iter::once(local_index_key(&healthy_path)))
            .collect();
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
        while !inventory.step(&CodexTitleMetadata::default()) {}
        assert!(
            inventory.complete,
            "body loss does not erase proven header ownership"
        );
        let owner = original.headers[0].owner.clone();
        let group = inventory
            .groups()
            .remove(&group_key(&root, &owner))
            .unwrap();
        assert_eq!(group.members.len(), 2);
        assert!(matches!(
            replay_group(group, None, &ScanIndex::default()),
            Err(GroupEnd::Strict)
        ));
        let affected = inventory.affected_owners();
        assert!(inventory.membership_complete(&owner, affected.as_ref()));
        assert!(inventory.membership_complete(healthy, affected.as_ref()));
        let validation = Validation::new(
            inventory.clone(),
            Vec::new(),
            &BTreeSet::from([healthy.into()]),
            paths,
        );
        assert!(validation.validate_all().is_ok());
        fs::write(&healthy_path, b"{malformed}\n").unwrap();
        assert!(validation.validate_all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn write_owner(path: &Path, owner: &str) {
        fs::write(
            path,
            format!(
                "{}\n",
                json!({"type":"session_meta","payload":{"id":owner}})
            ),
        )
        .unwrap();
    }
    fn roster(inventory: &HeaderInventory) -> BTreeSet<String> {
        inventory
            .headers
            .iter()
            .map(|h| local_index_key(&h.candidate.path))
            .collect()
    }
    pub(super) fn validator(inventory: HeaderInventory) -> Validation {
        let paths = roster(&inventory);
        let owners = BTreeSet::from([inventory.headers[0].owner.clone()]);
        Validation::new(inventory, Vec::new(), &owners, paths)
    }
    fn validation_error(validation: &Validation) -> String {
        crate::snapshot_sync::safe_error(&validation.validate_all().unwrap_err())
    }

    /// [regress] Every home constrains this page's owners. Unrelated changes
    /// defer, while cross-home collisions and unreadable headers fail closed.
    #[test]
    fn surviving_singleton_revalidates_its_owners_across_all_homes() {
        let (root, original) = fixture();
        let sessions = root.join("sessions");
        let other_root = crate::test_scratch::unique_path("ottto-codex-join-other");
        let other = other_root.join("sessions");
        fs::create_dir_all(&other).unwrap();
        let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
        let remote = "dddddddd-1111-4111-8111-dddddddddddd";
        let healthy_path = sessions.join("healthy.jsonl");
        let remote_path = other.join("remote.jsonl");
        write_owner(&healthy_path, healthy);
        write_owner(&remote_path, remote);
        let mut paths = roster(&original);
        paths.extend([
            local_index_key(&healthy_path),
            local_index_key(&remote_path),
        ]);
        let mut directories = DirectoryCensus::new();
        for directory in [&sessions, &other] {
            directories.observe(directory, &fs::metadata(directory).unwrap());
        }
        let roots = [sessions.clone(), other.clone()];
        let mut inventory = HeaderInventory::new(&roots, &paths, Some(&directories));
        while !inventory.step(&CodexTitleMetadata::default()) {}
        let owner = original.headers[0].owner.clone();
        let selected = BTreeSet::from([owner.clone(), healthy.into()]);
        let validation = Validation::new(inventory.clone(), Vec::new(), &selected, paths.clone());
        // Count flips 3 -> 4: remote headers now participate too.
        assert_eq!(validation.validate_all().unwrap(), 4);
        write_owner(&remote_path, healthy);
        // Cross-home rewrite flips success -> the ownership phrase.
        assert_eq!(validation_error(&validation), HEADER_OWNERSHIP_CHANGED);
        let mut next = HeaderInventory::new(&roots, &paths, Some(&directories));
        while !next.step(&CodexTitleMetadata::default()) {}
        let affected = next.affected_owners();
        assert!(!next.membership_complete(healthy, affected.as_ref()));
        assert!(next.membership_complete(&owner, affected.as_ref()));
        fs::write(&remote_path, b"{unknown}\n").unwrap();
        fs::write(other.join("late.jsonl"), b"{unknown}\n").unwrap();
        assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
        // Restore remote proof first so malformed files do not mask ownership.
        fs::remove_file(other.join("late.jsonl")).unwrap();
        write_owner(&remote_path, remote);
        write_owner(&healthy_path, remote);
        assert_eq!(
            crate::snapshot_sync::safe_error(
                &validation
                    .validate(&BTreeSet::from([healthy.into()]))
                    .unwrap_err()
            ),
            HEADER_OWNERSHIP_CHANGED
        );
        // Every owner rewrite remains fail-closed, even for unrelated owners.
        assert_eq!(
            crate::snapshot_sync::safe_error(
                &validation
                    .validate(&BTreeSet::from([owner.clone()]))
                    .unwrap_err()
            ),
            HEADER_OWNERSHIP_CHANGED
        );
        write_owner(&healthy_path, healthy);
        assert!(validation.validate_all().is_ok());
        // A classified new member names the page owner in either home.
        for directory in [&other, &sessions] {
            let late = directory.join("late.jsonl");
            write_owner(&late, &owner);
            assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
            fs::remove_file(late).unwrap();
        }
        // Phrase flips: an unclassified late header fails its read.
        fs::write(sessions.join("late.jsonl"), b"{unknown}\n").unwrap();
        assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(other_root).unwrap();
    }

    /// [regress] An unrelated session created mid-page no longer rejects the page.
    #[test]
    fn owner_scoped_unrelated_new_session_mid_page_saves() {
        let (root, _) = fixture();
        let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
        write_owner(&root.join("sessions/new.jsonl"), "unrelated");
        result
            .codex_joining_validator()
            .unwrap()
            .validate(&result.snapshots)
            .unwrap();
        result.validate_codex_checkpoint().unwrap();
        result.finish_codex_capture_boundary(&mut index);
        let state = root.join("index.json");
        index.save(&state).unwrap();
        assert!(state.is_file());
        fs::remove_dir_all(root).unwrap();
    }

    /// [money] A midnight directory defers without losing its read obligation.
    #[test]
    fn owner_scoped_midnight_directory_deferred_then_read_money_oracle() {
        use sampled_scan::transition_fixture::{money_oracle, scan_money};

        let (root, _) = fixture();
        // Use one physical member per owner, as scan_money expects emitted
        // entities rather than the joined group's pre-upload aliases.
        fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
        let old_day = root.join("sessions/2026/10/06");
        fs::create_dir_all(&old_day).unwrap();
        fs::rename(root.join("sessions/a.jsonl"), old_day.join("a.jsonl")).unwrap();
        let write_member = |path: &Path, owner: &str| {
            fs::write(
                path,
                member(owner, "response", 50, 50)
                    .iter()
                    .map(|row| format!("{row}\n"))
                    .collect::<String>(),
            )
            .unwrap();
        };
        // Keep an ordinary census page owed, so catch-up uses retained refresh.
        write_member(
            &old_day.join("z.jsonl"),
            "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb",
        );
        let previous = ScanIndex::default();
        let (mut index, mut first) = scan(&root, previous.clone(), 1);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut first, &mut index);
        assert!(!first.census_complete);
        assert_eq!(first.snapshots.len(), 1);

        let day = root.join("sessions/2026/10/07");
        let path = day.join("new.jsonl");
        let owner = "cccccccc-1111-4111-8111-cccccccccccc";
        fs::create_dir(&day).unwrap();
        write_member(&path, owner);
        first
            .codex_joining_validator()
            .unwrap()
            .validate(&first.snapshots)
            .unwrap();
        first.validate_codex_checkpoint().unwrap();
        first.finish_codex_capture_boundary(&mut index);
        let accepted = first
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect();
        index = index.committable_subset(&previous, &accepted, &BTreeMap::new());
        let state = root.join("index.json");
        index.save(&state).unwrap();
        index = ScanIndex::load(&state).unwrap();
        assert!(!index
            .traversal
            .as_ref()
            .unwrap()
            .codex_join_directory_census
            .as_ref()
            .unwrap()
            .contains(&day));
        refresh_retained_codex_roster(SnapshotSource::Codex, &mut index, 7, None);
        assert!(index
            .traversal
            .as_ref()
            .unwrap()
            .pending_directories
            .iter()
            .any(|queued| queued.path == day));
        assert!(!index.files.contains_key(&local_index_key(&path)));

        let previous = index.clone();
        let (mut index, mut later) = scan(&root, index, 8);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut later, &mut index);
        assert!(later.census_complete);
        later.validate_codex_checkpoint().unwrap();
        assert_eq!(
            later
                .completed_parses()
                .filter(|(key, _)| *key == local_index_key(&path))
                .count(),
            1
        );
        assert_eq!(
            later
                .snapshots
                .iter()
                .filter(|s| s.source_session_id == owner)
                .count(),
            1
        );
        let accepted = later
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect();
        later.finish_codex_capture_boundary(&mut index);
        index = index.committable_subset(&previous, &accepted, &BTreeMap::new());
        index.save(&state).unwrap();
        let (_, quiet) = scan(&root, ScanIndex::load(&state).unwrap(), 8);
        assert_eq!(
            quiet.scanned_file_count, 0,
            "no repeated body read after catch-up"
        );
        assert!(quiet.snapshots.is_empty());

        let (mut cold_index, mut cold) = scan(&root, ScanIndex::default(), 8);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut cold, &mut cold_index);
        later.snapshots.extend(first.snapshots.clone());
        for items in [&mut cold.snapshots, &mut later.snapshots] {
            items.sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
        }
        let expected = scan_money(SnapshotSource::Codex, &cold_index, &cold);
        let deferred = scan_money(SnapshotSource::Codex, &index, &later);
        let prior = scan_money(SnapshotSource::Codex, &index, &first);
        money_oracle::assert_equivalent(&expected, &deferred);
        money_oracle::assert_no_smaller_reemit(owner, &prior, &deferred, &expected, false);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_new_file_naming_page_owner_fails_before_upload() {
        let (root, inventory) = fixture();
        let owner = inventory.headers[0].owner.clone();
        let validation = validator(inventory);
        write_owner(&root.join("sessions/new.jsonl"), &owner);
        assert_eq!(
            crate::snapshot_sync::safe_error(
                &validation.validate(&BTreeSet::from([owner])).unwrap_err()
            ),
            DIRECTORY_MEMBERSHIP_CHANGED
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_unrelated_compression_and_vanishing_defer() {
        let (root, original) = fixture();
        let sessions = root.join("sessions");
        let other = "ffffffff-1111-4111-8111-ffffffffffff";
        let plain = sessions.join(format!("rollout-{other}.jsonl"));
        write_owner(&plain, other);
        let mut paths = roster(&original);
        paths.insert(local_index_key(&plain));
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory =
            HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
        while !inventory.step(&CodexTitleMetadata::default()) {}
        let owners = BTreeSet::from([original.headers[0].owner.clone()]);
        let validation = Validation::new(inventory, Vec::new(), &owners, paths);
        let archive = plain.with_extension("jsonl.zst");
        fs::write(
            &archive,
            zstd::stream::encode_all(fs::read(&plain).unwrap().as_slice(), 0).unwrap(),
        )
        .unwrap();
        assert!(validation.validate_all().is_ok());
        fs::remove_file(&plain).unwrap();
        assert!(validation.validate_all().is_ok());
        fs::remove_file(&archive).unwrap();
        assert!(validation.validate_all().is_ok());
        fs::write(sessions.join("x.jsonl.zst"), b"not zstd").unwrap();
        assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_owner_compression_defers_until_plaintext_vanishes() {
        let (root, inventory) = fixture();
        let validation = validator(inventory);
        let plain = root.join("sessions/a.jsonl");
        fs::write(
            plain.with_extension("jsonl.zst"),
            zstd::stream::encode_all(fs::read(&plain).unwrap().as_slice(), 0).unwrap(),
        )
        .unwrap();
        // A shadow beside an owner's plaintext adds no membership fact.
        assert!(validation.validate_all().is_ok());
        assert!(validation.validate_all().is_ok());
        fs::remove_file(plain).unwrap();
        assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_vanished_page_member_fails() {
        let (root, inventory) = fixture();
        let validation = validator(inventory);
        fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
        assert_eq!(validation_error(&validation), HEADER_STAT_FAILED);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_empty_new_subdirectory_mid_page_saves() {
        let (root, inventory) = fixture();
        let validation = validator(inventory);
        fs::create_dir(root.join("sessions/new-day")).unwrap();
        validation.validate_all().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_nested_new_directories_defer_unrelated_rollouts() {
        let (root, inventory) = fixture();
        let validation = validator(inventory);
        let day = root.join("sessions/2027/01/01");
        fs::create_dir_all(&day).unwrap();
        write_owner(&day.join("unrelated.jsonl"), "unrelated");
        validation.validate_all().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_new_directory_same_owner_subagent_fails_before_upload() {
        let (root, inventory) = fixture();
        let owner = inventory.headers[0].owner.clone();
        let validation = validator(inventory);
        let day = root.join("sessions/new-day");
        fs::create_dir(&day).unwrap();
        fs::write(
            day.join("subagent.jsonl"),
            format!(
                "{}\n",
                json!({
                    "type":"session_meta", "payload":{"id":owner,
                        "source":{"subagent":{"fork":{"parent_thread_id":owner}}}}
                })
            ),
        )
        .unwrap();
        assert_eq!(
            crate::snapshot_sync::safe_error(
                &validation.validate(&BTreeSet::from([owner])).unwrap_err()
            ),
            DIRECTORY_MEMBERSHIP_CHANGED
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_new_directory_unsettled_header_fails_closed() {
        let (root, inventory) = fixture();
        let validation = validator(inventory);
        let day = root.join("sessions/new-day");
        fs::create_dir(&day).unwrap();
        fs::write(day.join("unsettled.jsonl"), b"{\"type\":\"session_meta\"").unwrap();
        assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_vanished_directory_mid_page_fails() {
        let (root, mut inventory) = fixture();
        let sessions = root.join("sessions");
        let directory = sessions.join("old-day");
        fs::create_dir(&directory).unwrap();
        inventory.directories = DirectoryCensus::new();
        for path in [&sessions, &directory] {
            inventory
                .directories
                .observe(path, &fs::metadata(path).unwrap());
        }
        let validation = validator(inventory);
        fs::remove_dir(directory).unwrap();
        assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_known_roster_entries_need_no_header_proof() {
        let (root, original) = fixture();
        let owner = original.headers[0].owner.clone();
        let mut paths = roster(&original);
        // Shadowed, carry-deferred and held files are roster facts, even when
        // there is deliberately no inventory header for their path.
        for name in ["a.jsonl.zst", "deferred.jsonl", "held.jsonl.zst"] {
            let path = root.join("sessions").join(name);
            fs::write(&path, b"held").unwrap();
            paths.insert(local_index_key(&path));
        }
        let mut inventory = original;
        inventory.directories = DirectoryCensus::new();
        inventory.directories.observe(
            &root.join("sessions"),
            &fs::metadata(root.join("sessions")).unwrap(),
        );
        let validation = Validation::new(inventory, Vec::new(), &BTreeSet::from([owner]), paths);
        write_owner(&root.join("sessions/new.jsonl"), "unrelated");
        assert!(validation.validate_all().is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_archive_never_trusts_a_vanished_predecessor_owner() {
        let (root, original) = fixture();
        let owner = original.headers[0].owner.clone();
        let sessions = root.join("sessions");
        let plain = sessions.join(format!("rollout-{owner}.jsonl"));
        write_owner(&plain, "unrelated");
        let mut paths = roster(&original);
        paths.insert(local_index_key(&plain));
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
        while !inventory.step(&CodexTitleMetadata::default()) {}
        let validation = Validation::new(inventory, Vec::new(), &BTreeSet::from([owner]), paths);
        fs::write(plain.with_extension("jsonl.zst"), b"held").unwrap();
        assert!(validation.validate_all().is_ok());
        fs::remove_file(plain).unwrap();
        assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_scoped_unshadowed_roster_archive_fences_only_page_owners() {
        for candidate in [
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "cccccccc-1111-4111-8111-cccccccccccc",
            "",
        ] {
            let (root, original) = fixture();
            let owner = original.headers[0].owner.clone();
            let sessions = root.join("sessions");
            let other = root.join("other-home/sessions");
            fs::create_dir_all(&other).unwrap();
            let name = if candidate.is_empty() {
                "anonymous.jsonl".into()
            } else {
                format!("rollout-{candidate}.jsonl")
            };
            let plain = other.join(name);
            write_owner(&plain, "unrelated-b");
            let archive = plain.with_extension("jsonl.zst");
            // Undecodable bytes prove this boundary uses the filename only.
            fs::write(&archive, b"held archive, no decoding").unwrap();
            let mut paths = roster(&original);
            paths.extend([local_index_key(&plain), local_index_key(&archive)]);
            let mut directories = DirectoryCensus::new();
            for directory in [&sessions, &other] {
                directories.observe(directory, &fs::metadata(directory).unwrap());
            }
            let mut inventory =
                HeaderInventory::new(&[sessions, other], &paths, Some(&directories));
            while !inventory.step(&CodexTitleMetadata::default()) {}
            assert!(
                inventory.owner_for_path(&archive).is_none(),
                "roster archive starts shadowed"
            );
            let validation = Validation::new(
                inventory,
                Vec::new(),
                &BTreeSet::from([owner.clone()]),
                paths,
            );
            assert!(validation.validate_all().is_ok());
            fs::remove_file(plain).unwrap();
            let selected = BTreeSet::from([owner.clone()]);
            if candidate == owner {
                assert_eq!(
                    crate::snapshot_sync::safe_error(&validation.validate(&selected).unwrap_err()),
                    DIRECTORY_MEMBERSHIP_CHANGED
                );
                assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
            } else if candidate.is_empty() {
                assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
            } else {
                assert!(validation.validate(&selected).is_ok());
                assert!(validation.validate_all().is_ok());
            }
            fs::remove_dir_all(root).unwrap();
        }
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
        assert!(parsed.progress_complete());
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
            None,
            &[],
            false,
        );
        // A reader step is one line; one fixture member holds ~1,030 lines.
        for _ in 0..10_000 {
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
    /// proves native-turn UI).
    pub(crate) fn counting_v2_fixture() -> (PathBuf, [String; 2]) {
        counting_v2_fixture_with(true)
    }
    /// #603's original rows: UI in an unbound span, which a V2 group holds.
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
        let (legacy_index, legacy) = {
            // The fixture's October 1 headers predate the frozen cutover.
            let _cutover = codex_counting_version::TestCutover::set(
                codex_counting_version::CODEX_COUNTING_V2_CUTOVER_UNIX_MS,
            );
            scan(&root, ScanIndex::default(), 2)
        };
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
        let legacy_receipts = legacy
            .codex_counting_v2
            .as_deref()
            .expect("a pre-cutover Legacy scan still reports bookkeeping");
        assert_eq!(legacy_receipts.v2_sessions, 0);
        assert_eq!(legacy_receipts.native_counted, 0);
        assert_eq!(legacy_receipts.tombstone_count, 0);
        assert_eq!(
            legacy_receipts.tombstone_cap,
            codex_counting_version::MAX_COUNTING_TOMBSTONES as u64
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
            Some(Arc::new(traces)),
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
        assert!(parsed.progress_complete());
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
            None,
            &[],
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
    fn bad_native_record_preserves_the_complete_joined_replacement() {
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
        // A valid new occurrence makes this a new body, rather than an
        // unchanged accepted300 body that policy correctly suppresses.
        for row in member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 100, 400)
            .into_iter()
            .skip(1)
        {
            text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
        }
        fs::write(&path, text).unwrap();
        let (mut after, mut current) = scan(&root, previous.clone(), 2);
        let (mut cold_index, mut cold) = scan(&root, ScanIndex::default(), 2);
        assert_eq!(current.snapshots.len(), 2, "one alias per physical member");
        assert!(current.snapshots.iter().all(|s| s.input_tokens == 400));
        assert_eq!(current.recognized_usage_drop_count, 1);
        assert_eq!(current.ownership_incomplete_file_count, 0);
        current
            .codex_joining_validator()
            .unwrap()
            .validate(&current.snapshots)
            .unwrap();
        finalize_scan_after_policy(SnapshotSource::Codex, &mut current, &mut after);
        current.finish_codex_capture_boundary(&mut after);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut cold, &mut cold_index);
        cold.finish_codex_capture_boundary(&mut cold_index);
        assert_eq!(
            serde_json::to_value(&current.snapshots).unwrap(),
            serde_json::to_value(&cold.snapshots).unwrap()
        );
        let accepted = current
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(accepted.len(), 1, "one body identity across both aliases");
        assert_eq!(
            serde_json::to_value(
                &after
                    .committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new())
                    .files
            )
            .unwrap(),
            serde_json::to_value(&previous.files).unwrap(),
            "no ACK cannot settle either alias"
        );
        let mut settled = after.committable_subset(&previous, &accepted, &BTreeMap::new());
        let state = root.join("index.json");
        settled.save(&state).unwrap();
        let (_, quiet) = scan(&root, ScanIndex::load(&state).unwrap(), 2);
        assert!(quiet.snapshots.is_empty());
        assert_eq!(quiet.semantic_noop_count, 2);
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
            None,
            &[],
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
    fn replay_owner_rewrite_after_inventory_cannot_escape_validation() {
        let (root, _) = fixture();
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            ScanIndex::default(),
            "2026-10-06T23:00:00Z",
            7,
            2,
            None,
            &[],
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
            None,
            &[],
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
                    let error = scan
                        .validate_codex_checkpoint()
                        .expect_err("no-op suppression cannot make a stale checkpoint eligible");
                    // The failure names its own check, never the bare phrase.
                    let shown = crate::snapshot_sync::safe_error(&error);
                    assert_ne!(shown, "sync failed");
                    assert!(CODEX_JOIN_VALIDATION_FAILURES.contains(&shown.as_str()));
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
            None,
            hints,
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
    /// [money] Protected history survives retirement; quiet retries acquire,
    /// enqueue and count nothing.
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
            None,
            &[],
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
    fn missing_protected_receipt_rewrite_holds_correction_but_scope_does_not() {
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
        for (rows, scope, holds) in [
            (changed.as_slice(), "scope", true),
            (rows.as_slice(), "other-scope", false),
        ] {
            let mut replay = TierReplay::new(Some(receipt.clone()), true, scope.into());
            for row in rows {
                replay.observe(row);
            }
            replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
            assert_eq!(replay.finish().is_err(), holds, "{scope}");
        }
        // [regress] No per-file tier cap: 513 priority contributions (one past
        // the former 512) finish, and their receipt replays as valid.
        let many = (0..513)
            .map(|i| (format!("{i:064x}"), "derived_from_logs_2".to_string()))
            .collect::<Vec<_>>();
        let mut replay = TierReplay::new(None, false, "scope".into());
        for row in &rows {
            replay.observe(row);
        }
        for tier in &many {
            replay.admitted(Some(tier.clone()));
        }
        let receipt = replay.finish().unwrap().unwrap();
        assert_eq!(receipt.tiers.len(), 513);
        let mut replay = TierReplay::new(Some(receipt.clone()), true, "scope".into());
        assert!(!replay.invalid, "a receipt past 512 tiers is valid");
        for row in &rows {
            replay.observe(row);
        }
        for tier in &many {
            replay.admitted(Some(tier.clone()));
        }
        assert_eq!(replay.finish().unwrap(), Some(receipt));
    }
    #[test]
    fn malformed_or_missing_captured_metadata_holds_without_resetting_index() {
        for malformed in [Value::Null, json!({"version":"future","opaque":true})] {
            let root = native_join_fixture_root(true);
            let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
            finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
            let (mut captured, changed) =
                working.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
            assert_eq!(changed.len(), 1);
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
    /// `receipt` with 512 (the former per-file cap) synthetic priority
    /// contributions.
    fn full_receipt(receipt: &AppliedTierReceipt) -> AppliedTierReceipt {
        let mut full = receipt.clone();
        full.tiers = (0..512)
            .map(|n| {
                (
                    sha256_hex(&["synthetic-tier", &n.to_string()]),
                    "derived_from_logs_2".into(),
                )
            })
            .collect();
        full
    }
    /// [regress] Receipts past the former 2 MiB index aggregate no longer hold
    /// a recovery capture: the owner stages and every known selector stays.
    #[test]
    fn capture_past_former_receipt_aggregate_stages_owner_without_hold() {
        let root = native_join_fixture_root(true);
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let priced_key = local_index_key(&root.join("sessions/b.jsonl"));
        let priced = working.files[&priced_key]
            .codex_applied_tier_receipt
            .clone()
            .unwrap();
        let mut full = working.files[&priced_key].clone();
        full.codex_applied_tier_receipt = Some(full_receipt(&priced));
        let bytes = serde_json::to_vec(full.codex_applied_tier_receipt.as_ref().unwrap())
            .unwrap()
            .len();
        let former_aggregate = 2 * 1024 * 1024;
        let mut previous = ScanIndex::default();
        for n in 0..=(former_aggregate / bytes) {
            previous
                .files
                .insert(format!("synthetic-existing-{n}"), full.clone());
        }
        let (captured, changed) =
            working.stage_codex_recovery_capture(&previous, &result.snapshots);
        assert_eq!(changed.len(), 1, "the owner stages");
        assert_eq!(captured.files.len(), previous.files.len() + 2);
        assert_eq!(
            captured.files[&priced_key].codex_captured_tier_receipt,
            Some(priced)
        );
        assert!(captured.files[&priced_key].codex_captured_tier_receipt_required);
        for (key, entry) in &previous.files {
            assert_eq!(
                serde_json::to_value(&captured.files[key]).unwrap(),
                serde_json::to_value(entry).unwrap()
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
    /// [regress] A scan whose previous index retains more than the former
    /// 2 MiB of receipts emits the protected group, with no residue or hold.
    #[test]
    fn scan_past_former_receipt_aggregate_emits_protected_group() {
        let root = native_join_fixture_root(true);
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        // Other joined pairs: unchanged on the rescan, they only retain receipts.
        for pair in 1..=24u32 {
            let other = format!("{pair:08x}-bbbb-4ccc-8ddd-eeeeeeeeeeee");
            for (name, rows) in [
                ("a", member(&other, &format!("r-{pair}-a"), 100, 100)),
                ("b", member(&other, &format!("r-{pair}-b"), 200, 300)),
            ] {
                fs::write(
                    root.join(format!("sessions/x{pair}{name}.jsonl")),
                    rows.iter()
                        .map(|row| serde_json::to_string(row).unwrap() + "\n")
                        .collect::<String>(),
                )
                .unwrap();
            }
        }
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 64);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        result.finish_codex_capture_boundary(&mut working);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let mut previous =
            working.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        assert_eq!(previous.files.len(), 50);
        // The same index with only its real receipts: below the former aggregate.
        let below = previous.clone();
        let group =
            ["a", "b"].map(|name| local_index_key(&root.join(format!("sessions/{name}.jsonl"))));
        let full = full_receipt(
            previous.files[&group[1]]
                .codex_applied_tier_receipt
                .as_ref()
                .unwrap(),
        );
        let others = previous
            .files
            .keys()
            .filter(|key| !group.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        for key in &others {
            previous
                .files
                .get_mut(key)
                .unwrap()
                .codex_applied_tier_receipt = Some(full.clone());
        }
        assert!(others.len() * serde_json::to_vec(&full).unwrap().len() > 2 * 1024 * 1024);
        let path = root.join("sessions/b.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        for row in member(owner, "r-c", 200, 500).into_iter().skip(1) {
            text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
        }
        fs::write(&path, text).unwrap();
        let (after, rescanned) = scan(&root, previous, 64);
        let (below_after, below_rescanned) = scan(&root, below, 64);
        assert_eq!(rescanned.ownership_incomplete_file_count, 0);
        assert!(rescanned.census_complete);
        assert_eq!(rescanned.snapshots.len(), 2, "one alias per group member");
        assert!(rescanned
            .snapshots
            .iter()
            .all(|item| item.source_session_id == owner && item.input_tokens == 500));
        // Exact tokens and body: identical to the run below the former aggregate.
        assert_eq!(
            rescanned
                .snapshots
                .iter()
                .map(|item| serde_json::to_value(item).unwrap())
                .collect::<Vec<_>>(),
            below_rescanned
                .snapshots
                .iter()
                .map(|item| serde_json::to_value(item).unwrap())
                .collect::<Vec<_>>()
        );
        // A protected group defers traversal retirement to the capture
        // boundary, so the traversal is still present, with no residue.
        for index in [&after, &below_after] {
            assert!(index
                .traversal
                .as_ref()
                .expect("retirement waits for the capture boundary")
                .residue
                .index_keys
                .is_empty());
        }
        fs::remove_dir_all(root).unwrap();
    }
    /// [regress] T2: a joined group whose priced member grows past the former
    /// 512-tier cap still uploads, with no hold and every priced row priority.
    /// T3: with logs_2 gone, a replay from the saved index restores every tier
    /// from the receipt and emits a byte-identical body.
    #[test]
    fn joined_group_past_former_tier_cap_uploads_and_replays_without_downgrade() {
        let root = native_join_fixture_root(true);
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        result.finish_codex_capture_boundary(&mut working);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let previous =
            working.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
        let path = root.join("sessions/b.jsonl");
        let key = local_index_key(&path);
        let tiers = |index: &ScanIndex| {
            receipt_state(index.files.get(&key))
                .0
                .map_or(0, |receipt| receipt.tiers.len())
        };
        assert_eq!(tiers(&previous), 1);
        // 513 more admitted records under b's priority turn, 1 input token each.
        let mut text = fs::read_to_string(&path).unwrap();
        for i in 0..513u64 {
            for row in member(owner, &format!("r-t{i}"), 1, 301 + i)
                .into_iter()
                .skip(1)
            {
                text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
            }
        }
        fs::write(&path, text).unwrap();
        let (mut after, mut rescanned) = scan(&root, previous.clone(), 2);
        assert_eq!(rescanned.ownership_incomplete_file_count, 0);
        assert!(rescanned.census_complete);
        assert_eq!(rescanned.snapshots.len(), 2, "one alias per group member");
        for item in &rescanned.snapshots {
            assert_eq!(item.source_session_id, owner);
            // Fixture sum: a 100 + b 200 + 513 x 1.
            assert_eq!(item.input_tokens, 813);
            let priority = item
                .model_usage
                .iter()
                .filter(|row| {
                    row.selector_context.get("service_tier").map(String::as_str) == Some("priority")
                })
                .map(|row| row.input_tokens)
                .sum::<u64>();
            assert_eq!(priority, 713, "every b row is priced priority");
        }
        let body = rescanned
            .snapshots
            .iter()
            .map(|item| serde_json::to_value(item).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(tiers(&after), 514, "1 fixture tier + 513 appended");
        finalize_scan_after_policy(SnapshotSource::Codex, &mut rescanned, &mut after);
        let (capture, _) = after.stage_codex_recovery_capture(&previous, &rescanned.snapshots);
        rescanned.finish_codex_capture_boundary(&mut after);
        let accepted = rescanned
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        let mut committed = after.committable_subset(&capture, &accepted, &BTreeMap::new());
        let saved = root.join("index.json");
        committed.save(&saved).unwrap();
        let mut loaded = ScanIndex::load(&saved).unwrap();
        assert_eq!(tiers(&loaded), 514);
        // T3: the trace source expires; only the saved receipt can price b.
        fs::remove_file(root.join("logs_2.sqlite")).unwrap();
        loaded.prepare_historical_replay("tier-cap-replay".into());
        let (_, replayed) = scan(&root, loaded, 2);
        assert_eq!(replayed.ownership_incomplete_file_count, 0);
        assert_eq!(
            replayed
                .snapshots
                .iter()
                .map(|item| serde_json::to_value(item).unwrap())
                .collect::<Vec<_>>(),
            body,
            "restored from the receipt: no tier downgraded"
        );
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
        let (captured, changed) =
            working.stage_codex_recovery_capture(&previous, &result.snapshots);
        assert_eq!(changed.len(), 1);
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
        let (pending, _) =
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
        let (new_pending, changed) =
            expanded.stage_codex_recovery_capture(&pending, &result.snapshots);
        assert_eq!(changed.len(), 1);
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
        let (capture, _) = corrected.stage_codex_recovery_capture(&new_pending, &result.snapshots);
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
    fn unknown_version_preserves_protected_state() {
        let root = native_join_fixture_root(false);
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let (captured, _) =
            working.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
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
        let (pending, _) = working.stage_codex_recovery_capture(&previous, &result.snapshots);
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
        let (capture, changed) =
            corrected.stage_codex_recovery_capture(&pending, &result.snapshots);
        assert_eq!(changed.len(), 1);
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
                let (capture, _) =
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
                crate::snapshots::DiscoveryRetention::unverified(
                    &crate::snapshots::SharedMap::default(),
                ),
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
            )
            .unwrap();
            assert!(parsed.progress_complete());
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
        assert!(context.launch_events().prepared(&workers));
        context.expire_launch_lookup_for_test();
        assert!(!context.launch_events().prepared(&workers));
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
                cache: None,
                index: &previous,
            })
            .unwrap();
        let no_scope = |_: &CandidateFile| None;
        let inputs = StepInputs {
            metadata: &metadata,
            attribution: Some(&context),
            live_scope: &no_scope,
            cache: None,
            collected_at: "2026-10-01T12:00:00Z",
            index: &previous,
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
        assert!(context.launch_events().prepared(&workers));
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
    }
    pub(in crate::snapshots) fn page(
        root: &Path,
        paths: &BTreeSet<String>,
        cache: &Arc<sampled_scan::SharedCache>,
    ) -> HeaderInventory {
        let sessions = root.join("sessions");
        let mut census = DirectoryCensus::new();
        census.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inventory = HeaderInventory::new(&[sessions], paths, Some(&census));
        while !inventory.step_encoded(&CodexTitleMetadata::default(), Some(cache)) {}
        inventory
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
    fn unchanged_pages_reuse_without_reading_and_restart_is_cold() {
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = Arc::new(sampled_scan::SharedCache::default());
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
        let cold = page(
            &root,
            &paths,
            &Arc::new(sampled_scan::SharedCache::default()),
        );
        assert_eq!(facts(&cold), facts(&second));
        assert_eq!(cold.read_bytes, first.read_bytes);
        READ_CALLS.with(|calls| assert_eq!(calls.get(), paths.len()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn growth_and_replacement_refresh_once_failures_never_become_hits() {
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = Arc::new(sampled_scan::SharedCache::default());
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
        let cache = Arc::new(sampled_scan::SharedCache::default());
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
        cache.with_cursor(|cursor| cursor.headers.clear());
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
    /// [regress] A mandatory decoder claim that cannot fit beside the header
    /// facts in the shared state budget no longer clears them: the next
    /// unchanged archive walk reads 0 header bytes and opens no decoder, with
    /// the facts of a cold read. A replaced archive is read again, alone.
    #[test]
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux")),
        ignore = "needs validated heap layout"
    )]
    fn unchanged_archives_reuse_header_facts_after_decoder_pressure() {
        let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
        let (root, fixture) = tests::fixture();
        let archives = paths(&fixture)
            .into_iter()
            .map(|plain| {
                let plain = PathBuf::from(plain);
                let archive = plain.with_extension("jsonl.zst");
                let bytes = zstd::stream::encode_all(&fs::read(&plain).unwrap()[..], 1).unwrap();
                fs::write(&archive, bytes).unwrap();
                fs::remove_file(&plain).unwrap();
                local_index_key(&archive)
            })
            .collect::<BTreeSet<_>>();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let first = page(&root, &archives, &cache);
        assert!(first.complete);
        assert_eq!(first.reuse_misses, archives.len());
        assert!(first.read_bytes > 0);
        // Pressure: facts heavy enough that no decoder fits beside them.
        cache
            .with_cursor(|cursor| {
                let facts = cursor.headers.get(archives.first().unwrap()).unwrap();
                for number in 0..2 {
                    let mut key = format!("pressure-{number}");
                    key.reserve_exact(crate::transcript_cache::CACHE_BYTES / 8);
                    cursor.headers.refresh(key, Some(facts.clone()));
                }
            })
            .unwrap();
        let other = root.join("other.jsonl.zst");
        fs::write(&other, zstd::stream::encode_all(&b"{}\n"[..], 1).unwrap()).unwrap();
        crate::snapshots::codex_compressed_input::OpenedInput::funded(
            fs::File::open(&other).unwrap(),
            &cache,
        )
        .unwrap()
        .expect("the mandatory decoder is admitted")
        .close();
        READ_CALLS.with(|calls| calls.set(0));
        let second = page(&root, &archives, &cache);
        assert!(second.complete);
        assert_eq!(second.reuse_hits, archives.len());
        assert_eq!(second.reuse_misses, 0);
        assert_eq!(
            second.read_bytes, 0,
            "no header bytes after admission pressure"
        );
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 0, "no decoder opened"));
        let cold = page(
            &root,
            &archives,
            &Arc::new(sampled_scan::SharedCache::default()),
        );
        assert_eq!(facts(&second), facts(&cold));
        assert_eq!(facts(&first), facts(&cold));
        let replaced = PathBuf::from(archives.first().unwrap());
        let replacement = root.join("replacement");
        fs::write(&replacement, fs::read(&replaced).unwrap()).unwrap();
        fs::rename(&replacement, &replaced).unwrap();
        READ_CALLS.with(|calls| calls.set(0));
        let reread = page(&root, &archives, &cache);
        assert_eq!(reread.reuse_misses, 1, "a replaced object reads again");
        assert_eq!(reread.reuse_hits, archives.len() - 1);
        READ_CALLS.with(|calls| assert_eq!(calls.get(), 1));
        assert_eq!(facts(&reread), facts(&cold));
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn ctime_only_reuses_but_nanosecond_mtime_and_symlink_do_not() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (root, fixture) = tests::fixture();
        let paths = paths(&fixture);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        page(&root, &paths, &cache);
        let path = Path::new(paths.first().unwrap());
        let stat = fs::metadata(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let unchanged = page(&root, &paths, &cache);
        assert_eq!(unchanged.read_bytes, 0);
        // A refreshed ctime witness also avoids validation's fallback read.
        READ_CALLS.with(|calls| calls.set(0));
        tests::validator(unchanged).validate_all().unwrap();
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
