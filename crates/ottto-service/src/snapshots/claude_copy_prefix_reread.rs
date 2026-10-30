//! Explicit local scope; ordinary re-owe, selection, history budgets and ACKs
//! own execution. No transcript reader, uploader or scheduler lives here.
use super::*;
use anyhow::ensure;
use serde::{Deserialize, Serialize};
use std::io::Read;

const REQUEST: &str = "claude-copy-prefix-reread.json";
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
/// Local one-shot mark, carried with the existing settled money marks.
pub(super) const REOWED: u8 = 128;

#[derive(Clone, Serialize, Deserialize)]
struct Member {
    path: PathBuf,
    bytes: u64,
    birth: i128,
    modified: u128,
}
#[derive(Serialize, Deserialize)]
struct Request {
    members: Vec<Member>,
    window_days: u64,
}

/// Counts/durations only; never expose local scope identities.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Estimate {
    window_days: u64,
    files: usize,
    bytes: u64,
    pages: usize,
    blocked_files: usize,
    runnable_files: usize,
    runnable_bytes: u64,
    pacing_floor_seconds: u64,
    pacing_cold_seconds: u64,
}

fn bounded_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_REQUEST_BYTES,
        "scope exceeds existing local bound"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn member(path: &Path) -> Result<Member> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir)),
        "scope requires absolute paths"
    );
    ensure!(
        claude_index_path_member_ref(path).is_some_and(|m| m.subagent_stem.is_none()),
        "scope requires Claude main files"
    );
    let canonical = fs::canonicalize(path)?;
    ensure!(canonical == path, "scope refuses symlink paths");
    let stat = fs::symlink_metadata(path)?;
    ensure!(stat.is_file(), "scope requires regular files");
    let birth = stat.created()?.duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(Member {
        path: path.into(),
        bytes: stat.len(),
        birth: i128::try_from(birth)?,
        modified: stat.modified()?.duration_since(UNIX_EPOCH)?.as_nanos(),
    })
}
fn plan(mut members: Vec<Member>, window_days: u64) -> Result<Request> {
    ensure!(
        window_days <= BACKFILL_WINDOW_DAYS,
        "window exceeds existing policy"
    );
    ensure!(
        !members.is_empty() && members.len() <= MAX_BACKFILL_FILES_PER_SOURCE,
        "scope exceeds existing file bound"
    );
    ensure!(
        members
            .iter()
            .try_fold(0_u64, |sum, m| sum.checked_add(m.bytes))
            .is_some(),
        "scope byte count overflow"
    );
    members.sort_by(|a, b| (a.birth, &a.path).cmp(&(b.birth, &b.path)));
    let mut unique = BTreeSet::new();
    ensure!(
        members.iter().all(|m| unique.insert(&m.path)),
        "duplicate scope member"
    );
    Ok(Request {
        members,
        window_days,
    })
}
fn in_window(member: &Member, now: u64, days: u64) -> bool {
    u64::try_from(member.modified / 1_000_000_000)
        .ok()
        .is_some_and(|modified| is_recent_enough_at(modified, now, days))
}
fn runnable(member: &Member, now: u64, days: u64) -> bool {
    member.bytes <= max_jsonl_file_bytes(SnapshotSource::ClaudeCode)
        && member.bytes <= body_witness_adoption_byte_budget()
        && in_window(member, now, days)
}
fn estimate(request: &Request, now: u64) -> Estimate {
    let mut pages: usize = 0;
    let mut files = 0;
    let mut bytes = 0_u64;
    let mut blocked = 0;
    let mut runnable_files = 0;
    let mut runnable_bytes = 0;
    for m in &request.members {
        if !runnable(m, now, request.window_days) {
            blocked += 1;
            continue;
        }
        if files == 0
            || files >= body_witness_adoption_page_budget()
            || bytes.saturating_add(m.bytes) > body_witness_adoption_byte_budget()
        {
            pages += 1;
            files = 0;
            bytes = 0;
        }
        files += 1;
        bytes += m.bytes;
        runnable_files += 1;
        runnable_bytes += m.bytes;
    }
    let gaps = pages.saturating_sub(1) as u64;
    let (floor, cold) = crate::snapshot_sync::copy_prefix_pacing_seconds();
    Estimate {
        window_days: request.window_days,
        files: request.members.len(),
        bytes: request.members.iter().map(|m| m.bytes).sum(),
        pages,
        blocked_files: blocked,
        runnable_files,
        runnable_bytes,
        pacing_floor_seconds: gaps * floor,
        pacing_cold_seconds: gaps * cold,
    }
}

/// An operator-supplied private JSON array of exact main-file paths defines
/// the affected copy families. Estimate reads only scope + filesystem metadata.
/// Apply publishes a private request; it neither enables nor runs collection.
pub fn run(scope: &Path, support: &Path, apply: bool, window_days: u64) -> Result<Estimate> {
    let paths: Vec<PathBuf> = bounded_json(scope)?;
    ensure!(
        !paths.is_empty() && paths.len() <= MAX_BACKFILL_FILES_PER_SOURCE,
        "scope exceeds existing file bound"
    );
    let request = plan(
        paths.iter().map(|p| member(p)).collect::<Result<_>>()?,
        window_days,
    )?;
    let counts = estimate(
        &request,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    );
    if apply {
        ensure!(
            counts.blocked_files == 0,
            "scope outside existing window or page budget"
        );
        let encoded = serde_json::to_vec(&request)?;
        ensure!(
            encoded.len() as u64 <= MAX_REQUEST_BYTES,
            "scope exceeds existing local bound"
        );
        let dir = std::path::absolute(support.join("snapshots"))?;
        let created = dir
            .ancestors()
            .take_while(|path| !path.is_dir())
            .collect::<Vec<_>>();
        fs::create_dir_all(&dir)?;
        // Persist every new directory entry, starting at its existing parent.
        // An apply success must survive a crash even for a new support path.
        for path in created.into_iter().rev() {
            sync_checkpoint_parent(path)?;
        }
        // A create-new private file is published by atomic hard link; daemon
        // readers never see a partially written request. Existing intent wins.
        let temp = dir.join(format!(".copy-prefix-request-{}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        let result = (|| -> Result<()> {
            use std::io::Write;
            file.write_all(&encoded)?;
            file.sync_all()?;
            let published = dir.join(REQUEST);
            fs::hard_link(&temp, &published)?;
            sync_checkpoint_parent(&published)?;
            Ok(())
        })();
        let _ = fs::remove_file(&temp);
        result?;
    }
    Ok(counts)
}

/// Called under the existing sync lock, before the partial-commit baseline.
/// Scope metadata must still match; unindexed/outside-root members refuse the
/// whole request. Never create a new history bootstrap or touch a fingerprint.
pub(crate) fn prepare(
    index: &mut ScanIndex,
    support: &Path,
    roots: &[PathBuf],
    collected_at: &str,
    window_days: u64,
) -> Result<Vec<PathBuf>> {
    if !claude_request_money::e2::resumed_prefix_enabled() {
        return Ok(Vec::new());
    }
    let path = support.join("snapshots").join(REQUEST);
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    let request: Request = bounded_json(&path)?;
    let mut request = plan(request.members, request.window_days)?;
    ensure!(
        request.window_days == effective_backfill_window_days(window_days),
        "scope window changed; request refused"
    );
    let scan_now =
        rfc3339_unix_seconds(collected_at).ok_or_else(|| anyhow::anyhow!("invalid scan clock"))?;
    // Match discovery's supported configured-root symlink semantics. Scope
    // members and indexed keys use the resolved spelling, never a descendant
    // symlink or the configured alias.
    let mut census = ScanCensus::default();
    let resolved_roots = roots
        .iter()
        .filter_map(|root| {
            resolve_configured_scan_root(SnapshotSource::ClaudeCode, root, &mut census)
        })
        .collect::<Vec<_>>();
    for m in &mut request.members {
        let now = member(&m.path)?;
        ensure!(
            now.bytes == m.bytes && now.birth == m.birth && now.modified == m.modified,
            "scope metadata changed; request refused"
        );
        ensure!(
            runnable(m, scan_now, request.window_days),
            "scope outside scan window or native size bounds"
        );
        ensure!(
            resolved_roots.iter().any(|root| m.path.starts_with(root)),
            "scope outside source roots"
        );
        let key = local_index_key(&m.path);
        let entry = index
            .files
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("scope is not indexed"))?;
        ensure!(
            entry.size_bytes == m.bytes
                && entry
                    .modified_unix_nanos
                    .is_some_and(|n| u128::from(n) == m.modified),
            "scope differs from indexed extent"
        );
        let session = claude_index_path_member_ref(&m.path)
            .expect("validated main")
            .root;
        m.birth = index
            .claude_money_birth_store
            .effective_cutoff(session, &key)
            .map_or(m.birth, |b| b.min(m.birth));
    }
    request
        .members
        .sort_by(|a, b| (a.birth, &a.path).cmp(&(b.birth, &b.path)));
    let mut pending = Vec::new();
    for m in request.members {
        let key = local_index_key(&m.path);
        let location = claude_money_birth_store::location_key(&key);
        let marks = index.claude_money_birth_store.money_marks(location);
        if marks & REOWED == 0 {
            // Existing owner API: lower only to revision 2, never drop an
            // entry/census/ACK or bypass list and history admission.
            index.re_owe_effective_upload_body_witness_revision(&key, 2);
            index
                .claude_money_birth_store
                .set_money_marks(&key, marks | REOWED);
        }
        if index.effective_upload_body_witness_revision_requires_adoption(&key) {
            pending.push(m.path);
        }
    }
    Ok(pending)
}

/// Offer scoped debt before ordinary census/audits, earlier files first,
/// within the SAME selection limit. Native history admission still charges
/// all file/byte budgets and can hold it. No separate rate or continuation.
pub(super) fn select(
    index: &mut ScanIndex,
    scope: &[PathBuf],
    selected: &mut Vec<ScanTraversalPath>,
    limit: usize,
) {
    let mut page = claude_history_upgrade::HistoryPage::default();
    for path in scope {
        if selected.len() >= limit {
            break;
        }
        if selected.iter().any(|candidate| candidate.path == *path) {
            continue;
        }
        let key = local_index_key(path);
        if !index.effective_upload_body_witness_revision_requires_adoption(&key) {
            continue;
        }
        let Some(entry) = index.files.get(&key) else {
            continue;
        };
        if !page.reserve(&key, entry.size_bytes) {
            break;
        }
        if index.traversal.is_none() {
            break;
        }
        // A cancelled family carry may already owe this exact path. Consume
        // both queues before injecting priority work, preserving census/hint
        // facts while preventing two reads/folds of one physical file.
        let mut queued: Option<ScanTraversalPath> = None;
        {
            let mut take = |candidate: &ScanTraversalPath| {
                if candidate.path != *path {
                    return true;
                }
                if let Some(kept) = queued.as_mut() {
                    kept.census_member |= candidate.census_member;
                    kept.watcher_hint |= candidate.watcher_hint;
                } else {
                    queued = Some(candidate.clone());
                }
                false
            };
            index.claude_stale_family_carry.replay.retain(&mut take);
            index
                .traversal
                .as_mut()
                .expect("checked traversal")
                .pending_candidates
                .retain(&mut take);
        }
        let traversal = index.traversal.as_ref().expect("checked traversal");
        let candidate = queued.or_else(|| {
            let root = traversal
                .scan_roots
                .iter()
                .find(|root| path.starts_with(root))?;
            Some(ScanTraversalPath {
                scan_root: root.clone(),
                path: path.clone(),
                census_member: false,
                watcher_hint: false,
            })
        });
        if let Some(candidate) = candidate {
            selected.push(candidate);
        }
    }
}

/// A scoped unchanged revision re-read also owes its qualified context. That
/// second debt must not turn a history-budget hold into an ordinary read.
/// Real changes and independent audit/authority reasons keep their rules.
pub(super) fn unchanged_requested(index: &ScanIndex, candidate: &CandidateFile, now: u64) -> bool {
    let key = local_index_key(&candidate.path);
    claude_request_money::e2::resumed_prefix_enabled()
        && index
            .claude_money_birth_store
            .money_marks(claude_money_birth_store::location_key(&key))
            & REOWED
            != 0
        && index.copy_prefix_base_context_proven(&key)
        && index.files.get(&key).is_some_and(|entry| {
            entry.size_bytes == candidate.size_bytes
                && entry.modified_unix_seconds == candidate.modified_unix_seconds
                && entry.modified_unix_nanos == Some(candidate.modified_unix_nanos)
        })
        // Re-evaluate every independent reason without revision or mode
        // debt. Sidecar changes, retries and source changes must still parse
        // locally under history holds, as before this scoped mechanism.
        && index.candidate_decision_with_reason_gated(candidate, now, false, false).0 == CandidateDecision::Skip
}

#[cfg(test)]
mod tests;
