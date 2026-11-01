//! Oversized files are honest sweep-wide loss. Claude has content-driven,
//! cadence-bounded discovery retries and a six-hour recovery re-walk. This
//! state never enters an upload body.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Debt {
    content_hash: String,
    /// The public loss counter counts sightings, including duplicate hints.
    observations: usize,
    #[serde(default)]
    size_bytes: u64,
    /// Local scheduling clock; never uploaded. Older records start at the next sighting.
    #[serde(default)]
    first_seen_unix_seconds: u64,
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
        withheld_content_stamp: None,
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
            if old.first_seen_unix_seconds > 0 {
                debt.first_seen_unix_seconds = old.first_seen_unix_seconds;
            }
        }
        target.insert(key, debt);
    }
}

pub(super) fn record(
    source: SnapshotSource,
    scan_root: &Path,
    path: &Path,
    size_bytes: u64,
    debts: &mut BTreeMap<String, Debt>,
) {
    // Only Claude's existing recovery needs content samples. Other sources
    // retain metadata-only debt and keep their ordinary clock retry cadence.
    let (size_bytes, content_hash) = if source == SnapshotSource::ClaudeCode {
        content_witness(scan_root, path).unwrap_or((size_bytes, String::new()))
    } else {
        (size_bytes, String::new())
    };
    if size_bytes <= max_jsonl_file_bytes(source) {
        return;
    }
    let debt = debts.entry(path_hash(path)).or_insert_with(|| Debt {
        content_hash: String::new(),
        observations: 0,
        size_bytes,
        first_seen_unix_seconds: sampled_scan::now_seconds(),
    });
    debt.content_hash = content_hash;
    debt.size_bytes = size_bytes;
    debt.observations = debt.observations.saturating_add(1);
    if debt.first_seen_unix_seconds == 0 {
        debt.first_seen_unix_seconds = sampled_scan::now_seconds();
    }
}

/// Re-walks reset sighting counters, but never reset an outstanding alarm's age.
pub(super) fn restart(traversal: Option<&mut ScanTraversalCheckpoint>) -> BTreeMap<String, Debt> {
    let mut debts = traversal
        .map(|walk| std::mem::take(&mut walk.oversized_discovery))
        .unwrap_or_default();
    for debt in debts.values_mut() {
        debt.observations = 0;
    }
    debts
}

pub(super) fn alarm(source: SnapshotSource, traversal: &ScanTraversalCheckpoint) {
    let now = sampled_scan::now_seconds();
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    let mut age = 0_u64;
    for debt in traversal
        .oversized_discovery
        .values()
        .filter(|debt| debt.size_bytes > max_jsonl_file_bytes(source))
    {
        files += 1;
        bytes = bytes.saturating_add(debt.size_bytes);
        if debt.first_seen_unix_seconds > 0 {
            age = age.max(now.saturating_sub(debt.first_seen_unix_seconds));
        }
    }
    crate::local_resource_diagnostics::traversal_point(
        "oversized_discovery_alarm",
        source.api_slug(),
        &serde_json::json!({
            "outstanding_file_count": files,
            "outstanding_bytes": bytes,
            "first_seen_oversized_age_seconds": age,
        }),
    );
}

pub(super) fn release(counts: &mut ScanTraversalCounts, debt: Debt) {
    counts.oversized_file_count = counts
        .oversized_file_count
        .saturating_sub(debt.observations);
}

pub(super) fn clock_retry_required(
    source: SnapshotSource,
    traversal: &ScanTraversalCheckpoint,
) -> bool {
    if source != SnapshotSource::ClaudeCode {
        return traversal.counts.has_errors();
    }
    let mut counts = traversal.counts.clone();
    for debt in traversal
        .oversized_discovery
        .values()
        .filter(|debt| !debt.content_hash.is_empty())
    {
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
            let debt = traversal.oversized_discovery.get_mut(&hash).unwrap();
            debt.content_hash = content_hash;
            debt.size_bytes = size;
        } else {
            let scan_root = scan_root.clone();
            // Keep the age rescue until the ordinary open succeeds. A shrink
            // after the discovery window is still owed, not proof of a read.
            let debt = traversal.oversized_discovery.get_mut(&hash).unwrap();
            debt.content_hash = content_hash;
            debt.size_bytes = size;
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

crate::heap_layout_bound::fields!(Debt; content_hash, observations, size_bytes, first_seen_unix_seconds);
