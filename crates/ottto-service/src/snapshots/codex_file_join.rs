//! Local proof for joining physical Codex rollouts. Requested-tier selectors
//! retain the existing reader's meaning; response ownership is a separate fact.
use super::*;
use crate::transcript_acquisition::FileStamp;

mod custody;
mod group_job;
mod independent_fold;
pub(super) use custody::{fan_out_body_witnesses, fan_out_offered_to_aliases};
pub(super) use group_job::{
    disclose_members, disclose_strict, end_group, job_key, rearm_unsettled, refusal_disclosure,
    refuse_independent, step_group, take_charge, Boot, EndInputs, GroupBoot, GroupEnd, GroupJob,
    GroupStep, JobInputs, StepInputs,
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
    header_cache_tests::note_read(&candidate.path);
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
            durable: None,
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
/// Tail head continues, read as the inventory reads it.
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
    /// `Some(joined)`: a durable lookup's facts (through the joined-archive
    /// lookup when `joined`), reused in its place until the object changes or
    /// a commit may have changed the head. Never a RAM fallback.
    durable: Option<bool>,
}
#[derive(Default)]
pub(in crate::snapshots) struct HeaderCache {
    entries: BTreeMap<String, CachedHeader>,
    // The store whose committed heads the durable entries came from.
    durable_route: Option<PathBuf>,
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
    /// Drops durable entries whose head a commit may have changed: the
    /// `changed` keys, or all when `route` is another store or `changed` is
    /// unknown (`None`).
    pub(in crate::snapshots) fn forget_durable(
        &mut self,
        route: &Path,
        changed: Option<Vec<String>>,
    ) {
        let changed = match changed {
            Some(keys) if self.durable_route.as_deref() == Some(route) => keys,
            _ => {
                self.durable_route = Some(route.to_owned());
                self.entries.keys().cloned().collect()
            }
        };
        for key in changed {
            if self
                .entries
                .get(&key)
                .is_some_and(|header| header.durable.is_some())
            {
                self.refresh(key, None);
            }
        }
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
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.durable_route, c)?;
        c.add(self.heap_bytes)
    }
}
crate::heap_layout_bound::fields!(CachedHeader; stamp, owner, created_unix_ms, read_bytes, durable);
crate::heap_layout_bound::fields!(HeaderCache; entries, durable_route, heap_bytes, evictions);

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
    /// How often each `Incomplete` writer turned `complete` false. Counts only,
    /// for the page's census line; never persisted, never a gate.
    pub(super) incomplete_causes: IncompleteCauses,
}
/// Inline only, so the retained-heap walk visits it zero times.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct IncompleteCauses(pub(super) [usize; INCOMPLETE_CAUSE_NAMES.len()]);
crate::heap_layout_bound::no_heap!(true; IncompleteCauses);

/// Why `HeaderInventory::complete` went false, in `INCOMPLETE_CAUSE_NAMES` order.
#[derive(Clone, Copy)]
pub(super) enum Incomplete {
    CensusUnstable,
    CensusWalkPending,
    OutsideRoots,
    HeaderError,
    FundingRefused,
    SelectedNotInventoried,
}
const INCOMPLETE_CAUSE_NAMES: [&str; 6] = [
    "inventory_census_unstable",
    "inventory_census_walk_pending",
    "inventory_outside_roots",
    "inventory_header_error",
    "inventory_funding_refused",
    "inventory_selected_not_inventoried",
];

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

#[cfg(test)]
thread_local! {
    /// The hold counts each incomplete census line on this test thread
    /// reported, oldest first.
    static REPORTED_HOLD_COUNTS: std::cell::RefCell<Vec<(usize, bool, usize)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
/// Run `f` and return the hold counts its census lines reported.
#[cfg(test)]
fn observe_reported_hold_counts<T>(f: impl FnOnce() -> T) -> (Vec<(usize, bool, usize)>, T) {
    REPORTED_HOLD_COUNTS.with(|seen| seen.borrow_mut().clear());
    let value = f();
    (REPORTED_HOLD_COUNTS.with(|seen| seen.take()), value)
}
impl HeaderInventory {
    pub(super) fn new(
        roots: &[PathBuf],
        paths: &BTreeSet<String>,
        directories: Option<&DirectoryCensus>,
    ) -> Self {
        let mut inventory = Self {
            roots: roots.to_vec(),
            pending: paths
                .iter()
                .filter(|path| !shadowed_compressed_path(Path::new(path), paths))
                .map(PathBuf::from)
                .collect(),
            headers: Vec::new(),
            held_owners: group_job::unsealed_owners(paths),
            directories: directories.cloned().unwrap_or_default(),
            complete: true,
            read_bytes: 0,
            reuse_hits: 0,
            reuse_misses: 0,
            bytes_avoided: 0,
            reuse_evictions: 0,
            cache_pruned: false,
            refused: BTreeMap::new(),
            unreadable_causes: Default::default(),
            incomplete_causes: IncompleteCauses::default(),
        };
        let stable = directories.is_some_and(|value| value.stable);
        inventory.mark_incomplete(Incomplete::CensusUnstable, usize::from(!stable));
        inventory
    }
    /// `complete = false` when `count > 0`, counted under `cause`.
    pub(super) fn mark_incomplete(&mut self, cause: Incomplete, count: usize) {
        if count > 0 {
            self.complete = false;
            let slot = &mut self.incomplete_causes.0[cause as usize];
            *slot = slot.saturating_add(count);
        }
    }
    /// Count-only census-line fields for an incomplete inventory: which
    /// writers fired, and this page's hold (`record_codex_inventory_hold`).
    pub(super) fn incomplete_fields(
        &self,
        (held, awaiting, outside): (usize, bool, usize),
    ) -> Option<String> {
        (!self.complete).then(|| {
            #[cfg(test)]
            REPORTED_HOLD_COUNTS.with(|seen| seen.borrow_mut().push((held, awaiting, outside)));
            format!(
                " inventory_held={held} inventory_awaiting_directories={} inventory_outside_roster={outside} {}",
                u8::from(awaiting),
                census_count_fields(&INCOMPLETE_CAUSE_NAMES, &self.incomplete_causes.0)
            )
        })
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
            self.mark_incomplete(Incomplete::OutsideRoots, 1);
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
        let (mut lookups, mut reused_bytes) = (0, None);
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
            // Durable facts keep precedence; each later source runs only when
            // every earlier one missed. Any lookup that runs and errors fails the
            // member, as before.
            let joined = codex_archive_path(&candidate.path)
                && index.files.get(&key).is_some_and(|entry| {
                    entry.codex_joined_member_set.is_some()
                        && codex_index_file_body_accepted(index, &key, entry)
                });
            // One cache read per member, under the object's current stamp. A
            // durable entry stands in for its lookup (its store has dropped every
            // key a commit since may have changed); a file-derived one is the RAM
            // fallback after a durable miss.
            let route = cache.and_then(|_| state_v2::runtime_path(index).ok().flatten());
            let cached = cache
                .and_then(|cache| {
                    let consumer = std::ptr::from_ref::<sampled_scan::SharedCache>(cache).addr();
                    let changed = route.as_deref().map(|route| {
                        (
                            route,
                            state_v2::take_head_writes(route, consumer).ok().flatten(),
                        )
                    });
                    cache
                        .with_cursor(|cursor| {
                            if let Some((route, changed)) = changed {
                                cursor.headers.forget_durable(route, changed);
                            }
                            cursor.headers.get(&key)
                        })
                        .flatten()
                })
                .filter(|cached| {
                    cached.stamp.same_object(&stamp) && cached.stamp.same_content(&stamp)
                });
            let (carried, fallback) = match cached {
                Some(cached) if cached.durable.is_none() => (None, Some(cached)),
                Some(cached) if route.is_some() && cached.durable == Some(joined) => (
                    Some(CachedHeader {
                        stamp: stamp.clone(),
                        ..cached
                    }),
                    None,
                ),
                _ => (None, None),
            };
            let carried_hit = carried.is_some();
            let joined_archive = if !carried_hit && joined {
                lookups += 1;
                // Common facts only: any stored reduction revision serves.
                state_v2::load_head(index, &key, u32::MAX)?
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
                            durable: Some(joined),
                        })
                    })
            } else {
                None
            };
            let mut physical_match = false;
            let durable = match carried.or(joined_archive) {
                Some(facts) => Some(facts),
                None => {
                    lookups += 1;
                    index
                        .codex_physical_matches(&key, &current)?
                        .filter(|(matched, _)| {
                            physical_match = *matched;
                            *matched
                        })
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
                                durable: Some(joined),
                            })
                        })
                }
            };
            // An accepted Legacy file cannot be probed merely to rebuild an
            // inventory cache. Its existing owner and physical stamps suffice;
            // missing owner proof remains held until the content changes.
            let durable = if durable.is_none()
                && fallback.is_none()
                && sources::codex::counting::version::unchanged_legacy_with(index, &key, || {
                    physical_match
                        || index
                            .files
                            .get(&key)
                            .is_some_and(|entry| entry.same_listing_stamp_as(&current))
                }) {
                let owner_proof = index
                    .files
                    .get(&key)
                    .and_then(sources::codex::counting::version::proven_owner)
                    .context(HEADER_OWNERSHIP_CHANGED)?;
                let owner = codex_session_id_candidates_from_path(&candidate.path)
                    .into_iter()
                    .find(|session| codex_protected_owner(session) == owner_proof)
                    .map(|session| resolve_codex_identity(&session))
                    .context(HEADER_OWNERSHIP_CHANGED)?;
                Some(CachedHeader {
                    stamp: stamp.clone(),
                    owner,
                    created_unix_ms: None,
                    read_bytes: 0,
                    durable: Some(joined),
                })
            } else {
                durable
            };
            // Keep the lookup's facts for later inventories of this store.
            let keep = cache.filter(|_| route.is_some() && !carried_hit);
            if let Some((cache, facts)) = keep.zip(durable.as_ref()) {
                cache.refresh_header(key.clone(), Some(facts.clone()));
            }
            let reused = durable.or(fallback).map(|facts| {
                self.reuse_hits += 1;
                self.reuse_misses -= 1;
                self.bytes_avoided = self.bytes_avoided.saturating_add(facts.read_bytes);
                reused_bytes = Some(facts.read_bytes);
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
        if let Some(cache) = cache {
            cache.note_header_lookups(lookups, reused_bytes);
        }
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
                    let fenced = codex_archive_path(Path::new(&key)) && !owners.is_empty();
                    self.mark_incomplete(Incomplete::FundingRefused, usize::from(!fenced));
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
                self.mark_incomplete(Incomplete::HeaderError, 1);
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
crate::heap_layout_bound::fields!(HeaderInventory; roots, pending, headers, directories, complete, held_owners, read_bytes, reuse_hits, reuse_misses, bytes_avoided, reuse_evictions, cache_pruned, refused, unreadable_causes; inline incomplete_causes);

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
        // Common facts only: any stored reduction revision serves.
        let prior = state_v2::load_head(index, &key, u32::MAX)?;
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
    /// under V2 turn binding.
    pub(super) fn admitted_usage(
        &mut self,
        value: &Value,
        from_last: bool,
        identity: Option<&str>,
        turn: Option<&str>,
    ) {
        if let Some(join) = self.join.as_mut() {
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
        matches!(self, Self::Gap | Self::V2UiOnlyTurn)
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

/// A forked independent member may fold only when its header references the
/// parent history instead of carrying it: a paginated header that is either
/// the fork's own creation header (its ordinals start at the parent's base
/// end) or a revert whose base is this same session. Its physical records are
/// then its own, and a record repeated across members still refuses as an
/// admitted-key overlap. Members of different fork parents differ in
/// classification.
fn independent_fork_references_prefix(value: &Value, meta: &Value, owner: &str) -> bool {
    let base =
        resolve_codex_identity_option(codex_identity_at(meta, &["history_base", "thread_id"]));
    string_eq_at(meta, &["history_mode"], "paginated")
        && (codex_paginated_fork_creation_header(value, meta) || base.as_deref() == Some(owner))
}

/// The group proof, fed inside the one native replay: the native side in
/// `TierReplay::observe`, the UI side by the parser admission tap (S10)
/// after actual admission. It moves from member to member with the replay.
/// Only compact identities, counters and per-member ordinal witnesses are kept.
#[derive(Clone, Debug)]
pub(super) struct StreamProof {
    owner: String,
    independent: bool,
    independent_placement: Option<Option<(String, String)>>,
    independent_classification: Option<(Option<String>, Option<String>, Option<String>)>,
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
    // Fixed visits per walk: the compact sets are charged by
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
    pub(super) fn new(owner: String, plans: Vec<MemberPlan>) -> Self {
        Self {
            owner,
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
        let mut proof = Self::new(owner, vec![MemberPlan::default(); members]);
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
                    if (meta.get("forked_from_id").is_some_and(|v| !v.is_null())
                        && !independent_fork_references_prefix(value, meta, &self.owner))
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
                        meta.get("forked_from_id")
                            .filter(|v| !v.is_null())
                            .map(Value::to_string),
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
            if string_eq_at(value, &["type"], "token_usage_record") {
                self.observe_native(value)?;
            }
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
        if self.independent {
            return Ok(());
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
        if let Some(turn) = self.turn {
            self.native_turns.insert(turn);
        }
        Ok(())
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
            return Ok(());
        }
        codex_last_usage_root(value)
            .and_then(Tokens::read)
            .ok_or(JoinRefusal::UiShape)?;
        match turn {
            Some(turn) => {
                self.ui_turns.insert(compact(b"t:", turn));
            }
            None => self.unbound_ui = true,
        }
        Ok(())
    }

    /// Member EOF at physical offset `end`: duplicate-origin stubs must be
    /// neutral, and every UI admission must be backed by a native of the
    /// same turn in the group (V2).
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
        if self.refusal.is_some() || self.independent {
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
#[rustfmt::skip]
pub(super) mod tests;

#[cfg(all(test, unix))]
#[rustfmt::skip]
pub(in crate::snapshots) mod header_cache_tests;

#[cfg(all(test, unix))]
mod header_cache_output_tests;
