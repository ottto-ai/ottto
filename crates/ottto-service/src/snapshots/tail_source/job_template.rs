//! First-task state follows the authenticated file head, including native
//! publication that keeps no usable continuation checkpoint.
use super::*;
use crate::session_attribution::job_template::JobState;
use state_v2::{FileJob, JobUpdate, TailHead};

/// A Full read starts from byte zero, but it cannot reconsider a saved
/// decision. Indexed siblings rule out first observation for a joined run.
pub(in crate::snapshots) fn seed_full_job_template(
    index: &ScanIndex,
    candidate: &CandidateFile,
    group_siblings: &[CandidateFile],
    acc: &mut SnapshotAccumulator,
) -> anyhow::Result<()> {
    acc.job_template = None;
    acc.job_template_changed = false;
    let key = local_index_key(&candidate.path);
    let indexed = index.files.contains_key(&key);
    let load = || {
        if state_v2::tail_route_path(index)?.is_none() {
            return Ok((None, None));
        }
        state_v2::load_job_head(index, &key, reduction_revision(acc.source))
    };
    let (head, since) = match load() {
        Ok(loaded) => loaded,
        Err(_) if indexed => return Ok(()),
        Err(error) => return Err(error),
    };
    if let Some(head) = &head {
        restore_job(head, candidate, acc);
        if acc.job_template.is_some() {
            return Ok(());
        }
    }
    if indexed
        || load::held_new(index, &key)
        || group_siblings
            .iter()
            .any(|sibling| index.files.contains_key(&local_index_key(&sibling.path)))
    {
        return Ok(());
    }
    if let Some(since) = since.filter(|_| candidate.physical_identity.is_some()) {
        acc.job_template = Some(if candidate.fingerprint_birth_nanos >= since {
            JobState::Pending
        } else {
            JobState::NoId
        });
        acc.job_template_changed = true;
    }
    Ok(())
}

pub(super) fn restore_job(
    head: &TailHead,
    candidate: &CandidateFile,
    acc: &mut SnapshotAccumulator,
) {
    if head.job_corrupt {
        counters::bump(acc.source, "job_template_skipped", "stored_state");
    }
    let saved = head.common.job.as_ref();
    acc.job_template = saved
        .filter(|job| same_file(candidate, job.inode, job.birth_nanos))
        .map(|job| job.state.clone());
    acc.job_template_changed = head.job_corrupt || (saved.is_some() && acc.job_template.is_none());
}

pub(super) fn same_file(candidate: &CandidateFile, inode: u64, birth: u64) -> bool {
    let live_birth = candidate.fingerprint_birth_nanos;
    candidate
        .physical_identity
        .is_some_and(|[_, live]| live == inode)
        && same_birth(birth, live_birth, Some(candidate.modified_unix_nanos))
}

fn same_birth(saved: u64, live: u64, modified: Option<u64>) -> bool {
    saved == 0
        || live == 0
        || saved == live
        || crate::transcript_acquisition::birth_clamped_at(saved, live, modified)
}

/// Carry only the job that belongs to the proven predecessor reduction. The
/// destination may be a different inode after provider compression.
pub(in crate::snapshots) fn job_for_carry(
    head: &TailHead,
    inode: u64,
    birth_nanos: u64,
) -> Option<FileJob> {
    let job = head.common.job.as_ref()?;
    let cert = certified_certificate(&head.body).ok()?;
    let modified = u64::try_from(cert.modified.0)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|nanos| nanos.checked_add(u64::try_from(cert.modified.1).ok()?));
    if job.inode != cert.inode || !same_birth(cert.birth_nanos, job.birth_nanos, modified) {
        return None;
    }
    Some(FileJob {
        inode,
        birth_nanos,
        state: job.state.clone(),
    })
}

/// PRE captures only a changed decision. The caller stages it only after
/// the native result passes the graph publication gates.
pub(in crate::snapshots) fn job_update(
    candidate: &CandidateFile,
    acc: &SnapshotAccumulator,
) -> Option<JobUpdate> {
    if !acc.job_template_changed {
        return None;
    }
    Some(match &acc.job_template {
        Some(state) => {
            let [_, inode] = candidate.physical_identity?;
            JobUpdate::Set(FileJob {
                inode,
                birth_nanos: candidate.fingerprint_birth_nanos,
                state: state.clone(),
            })
        }
        None => JobUpdate::Clear,
    })
}
