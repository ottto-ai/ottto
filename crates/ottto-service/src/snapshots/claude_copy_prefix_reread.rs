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
}

/// Counts/durations only; never expose local scope identities.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Estimate {
    files: usize,
    bytes: u64,
    pages: usize,
    blocked_files: usize,
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
fn plan(mut members: Vec<Member>) -> Result<Request> {
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
    Ok(Request { members })
}
fn estimate(request: &Request) -> Estimate {
    let mut pages: usize = 0;
    let mut files = 0;
    let mut bytes = 0_u64;
    let mut blocked = 0;
    for m in &request.members {
        if m.bytes > body_witness_adoption_byte_budget() {
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
    }
    let gaps = pages.saturating_sub(1) as u64;
    let (floor, cold) = crate::snapshot_sync::copy_prefix_pacing_seconds();
    Estimate {
        files: request.members.len(),
        bytes: request.members.iter().map(|m| m.bytes).sum(),
        pages,
        blocked_files: blocked,
        pacing_floor_seconds: gaps * floor,
        pacing_cold_seconds: gaps * cold,
    }
}

/// An operator-supplied private JSON array of exact main-file paths defines
/// the affected copy families. Estimate reads only scope + filesystem metadata.
/// Apply publishes a private request; it neither enables nor runs collection.
pub fn run(scope: &Path, support: &Path, apply: bool) -> Result<Estimate> {
    let paths: Vec<PathBuf> = bounded_json(scope)?;
    ensure!(
        !paths.is_empty() && paths.len() <= MAX_BACKFILL_FILES_PER_SOURCE,
        "scope exceeds existing file bound"
    );
    let request = plan(paths.iter().map(|p| member(p)).collect::<Result<_>>()?)?;
    let counts = estimate(&request);
    if apply {
        ensure!(
            counts.blocked_files == 0,
            "scope cannot fit existing page budget"
        );
        let encoded = serde_json::to_vec(&request)?;
        ensure!(
            encoded.len() as u64 <= MAX_REQUEST_BYTES,
            "scope exceeds existing local bound"
        );
        let dir = support.join("snapshots");
        fs::create_dir_all(&dir)?;
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
            fs::hard_link(&temp, dir.join(REQUEST))?;
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
) -> Result<Vec<PathBuf>> {
    if !claude_request_money::e2::resumed_prefix_enabled() {
        return Ok(Vec::new());
    }
    let path = support.join("snapshots").join(REQUEST);
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    let request: Request = bounded_json(&path)?;
    let mut request = plan(request.members)?;
    for m in &mut request.members {
        let now = member(&m.path)?;
        ensure!(
            now.bytes == m.bytes && now.birth == m.birth && now.modified == m.modified,
            "scope metadata changed; request refused"
        );
        ensure!(
            roots.iter().any(|root| m.path.starts_with(root)),
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
        let Some(traversal) = index.traversal.as_mut() else {
            break;
        };
        let queued = traversal
            .pending_candidates
            .iter()
            .position(|p| p.path == *path)
            .and_then(|at| traversal.pending_candidates.remove(at));
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

#[cfg(test)]
mod tests;
