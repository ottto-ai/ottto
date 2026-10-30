//! Oversized Claude files are honest sweep-wide loss, with content-driven,
//! cadence-bounded discovery retries and a six-hour recovery re-walk. This
//! state never enters an upload body.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Debt {
    content_hash: String,
    /// The public loss counter counts sightings, including duplicate hints.
    observations: usize,
}

pub(super) fn path_hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(local_index_key(path).as_bytes()))
}

/// Only size and sampled bytes contribute. In particular, touching metadata
/// or replacing an object with the same content cannot change this marker.
fn content_witness(scan_root: &Path, path: &Path) -> std::io::Result<(u64, String)> {
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: scan_root.to_path_buf(),
        path: path.to_path_buf(),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        fingerprint_opened_identity: String::new(),
    };
    let mut file = open_candidate_beneath_root(&candidate)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let size = metadata.len();
    let mut digest = Sha256::new();
    digest.update(b"oversized-discovery-content:v1");
    digest.update(size.to_be_bytes());
    let mut buffer = [0_u8; 4096];
    let last = size.saturating_sub(buffer.len() as u64);
    for offset in [0, (size / 2).min(last), last] {
        file.seek(SeekFrom::Start(offset))?;
        let len = (size - offset).min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..len])?;
        digest.update(&buffer[..len]);
    }
    if file.metadata()?.len() != size {
        return Err(std::io::ErrorKind::WouldBlock.into());
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

pub(super) fn merge(target: &mut BTreeMap<String, Debt>, incoming: BTreeMap<String, Debt>) {
    for (key, mut debt) in incoming {
        if let Some(old) = target.get(&key) {
            debt.observations = debt.observations.saturating_add(old.observations);
        }
        target.insert(key, debt);
    }
}

pub(super) fn record(
    source: SnapshotSource,
    scan_root: &Path,
    path: &Path,
    debts: &mut BTreeMap<String, Debt>,
) {
    if source != SnapshotSource::ClaudeCode {
        return;
    }
    // A failed witness stays untracked retryable loss; never suppress its
    // existing clock recovery without the content evidence needed to wake it.
    if let Ok((size, content_hash)) = content_witness(scan_root, path) {
        // It may have shrunk between discovery's stat and this no-follow
        // sample. Leave that sighting on ordinary recovery, so a small-file
        // marker cannot suppress the parse that is now possible.
        if size <= MAX_CLAUDE_JSONL_FILE_BYTES {
            return;
        }
        let key = path_hash(path);
        let observations = debts
            .get(&key)
            .map_or(1, |old| old.observations.saturating_add(1));
        debts.insert(
            key,
            Debt {
                content_hash,
                observations,
            },
        );
    }
}

pub(super) fn clock_retry_required(
    source: SnapshotSource,
    traversal: &ScanTraversalCheckpoint,
) -> bool {
    if source != SnapshotSource::ClaudeCode {
        return traversal.counts.has_errors();
    }
    let mut counts = traversal.counts.clone();
    for debt in traversal.oversized_discovery.values() {
        counts.oversized_file_count = counts
            .oversized_file_count
            .saturating_sub(debt.observations);
    }
    counts.has_errors()
}

/// Full discovery is still needed for missed watcher events and blocking holds.
/// Anchor it to the durable traversal start, independently of content retries:
/// continuous growth must never push this recovery floor into the future.
pub(super) fn floor_retry_due(
    source: SnapshotSource,
    traversal: &ScanTraversalCheckpoint,
    collected_at: &str,
) -> bool {
    const FLOOR_SECONDS: u64 = 6 * 60 * 60;
    source == SnapshotSource::ClaudeCode
        && !traversal.oversized_discovery.is_empty()
        && rfc3339_unix_seconds(collected_at).map_or(true, |now| {
            rfc3339_unix_seconds(&traversal.census_window_end)
                .map_or(true, |started| now >= started.saturating_add(FLOOR_SECONDS))
        })
}

pub(super) fn retry_changed(traversal: &mut ScanTraversalCheckpoint, collected_at: &str) {
    if !traversal.pending_directories.is_empty()
        || !traversal.pending_candidates.is_empty()
        || traversal.oversized_discovery.is_empty()
        || clock_retry_required(SnapshotSource::ClaudeCode, traversal)
    {
        return;
    }
    let Some(now) = rfc3339_unix_seconds(collected_at) else {
        return;
    };
    let Some(deadline) = traversal.unhealthy_retry_not_before_unix_seconds else {
        return; // The ordinary terminal page installs the first deadline.
    };
    if now < deadline {
        return;
    }
    let mut changed = false;
    // Paths already belong to the local observation set; the new durable
    // marker adds hashes only. Never enumerate or invalidate other families.
    for key in &traversal.observed_index_keys {
        let path = Path::new(key);
        let hash = path_hash(path);
        let Some(debt) = traversal.oversized_discovery.get(&hash) else {
            continue;
        };
        let Some(scan_root) = traversal.owning_scan_root(path) else {
            continue;
        };
        let Ok((size, content_hash)) = content_witness(scan_root, path) else {
            continue; // Unknown content remains loss, not evidence of absence.
        };
        if content_hash == debt.content_hash {
            continue;
        }
        changed = true;
        if size > MAX_CLAUDE_JSONL_FILE_BYTES {
            // Retried this file's discovery cap, with the new content witness.
            traversal
                .oversized_discovery
                .get_mut(&hash)
                .unwrap()
                .content_hash = content_hash;
        } else {
            let scan_root = scan_root.clone();
            let debt = traversal.oversized_discovery.remove(&hash).unwrap();
            traversal.counts.oversized_file_count = traversal
                .counts
                .oversized_file_count
                .saturating_sub(debt.observations);
            traversal.pending_candidates.push_back(ScanTraversalPath {
                scan_root,
                path: path.to_path_buf(),
                census_member: true,
                watcher_hint: false,
            });
        }
    }
    if changed {
        // Exactly the existing exponential cadence, shared by the whole set:
        // continuous growth cannot turn every tick into another retry.
        traversal.unhealthy_retry_attempt = traversal
            .unhealthy_retry_attempt
            .saturating_add(1)
            .min(UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS);
        traversal.unhealthy_retry_not_before_unix_seconds = Some(now.saturating_add(
            unhealthy_scan_retry_delay_seconds(traversal.unhealthy_retry_attempt),
        ));
    }
}

crate::heap_layout_bound::fields!(Debt; content_hash, observations);
