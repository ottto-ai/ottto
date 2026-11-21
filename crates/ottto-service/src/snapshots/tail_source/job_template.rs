//! First-task state belongs to the published file, including a read that
//! cannot retain a continuation checkpoint.
use super::*;
use state_v2::JobTemplateObservation;

/// A native Full starts at byte zero, but job attribution belongs to the
/// run's first observation. Restore its durable decision independently of
/// the transcript checkpoint, which may have been invalidated by an edit.
pub(in crate::snapshots) fn seed_full_job_template(
    index: &ScanIndex,
    candidate: &CandidateFile,
    acc: &mut SnapshotAccumulator,
) {
    let key = local_index_key(&candidate.path);
    acc.job_template_pending = !index.files.contains_key(&key) && !load::held_new(index, &key);
    // A route error gives no first-read authority. Other snapshot fields
    // still use the existing native recovery path.
    let route = match state_v2::tail_route_path(index) {
        Ok(Some(route)) => route,
        Ok(None) => return,
        Err(_) => {
            acc.job_template_pending = false;
            return;
        }
    };
    match restore_job_template_observation(index, &key, candidate, acc) {
        Ok(true) => return,
        Ok(false) => {}
        Err(_) => {
            acc.job_template_pending = false;
            return;
        }
    }
    let (head, fact) =
        match state_v2::load_job_template(index, &key, reduction_revision(acc.source)) {
            Ok(Some(saved)) => saved,
            Ok(None) => return,
            Err(_) => {
                acc.job_template_pending = false;
                return;
            }
        };
    acc.job_template_pending = false;
    let id = HeadIdentity::new(
        &route,
        acc.source,
        &candidate.scan_root,
        &candidate.path,
        acc.claude_request_identity_capture,
    );
    let mut decoder = Dec::new(&head.body);
    let Ok(saved) = HeadIdentity::take(&mut decoder) else {
        return;
    };
    // Key changes affect upload policy, not the saved decision. Device
    // numbers can change across boots; the inode and known birth bind it.
    if saved.binding != id.binding {
        return;
    }
    let Ok(certificate) = DurableCertificate::take(&mut decoder) else {
        return;
    };
    if !same_file(candidate, certificate.inode, certificate.birth_nanos) {
        return;
    }
    if let Some(bytes) = fact {
        let _ = Fact::take(state_v2::JOB_TEMPLATE_PAGE, &bytes, acc);
    } else {
        acc.job_template_pending = head.common.job_template_pending;
    }
}

pub(super) fn same_file(candidate: &CandidateFile, inode: u64, birth: u64) -> bool {
    let live_birth = candidate.fingerprint_birth_nanos;
    candidate
        .physical_identity
        .is_some_and(|[_, live]| live == inode)
        && (birth == 0
            || live_birth == 0
            || birth == live_birth
            || crate::transcript_acquisition::birth_clamped_at(
                birth,
                live_birth,
                Some(candidate.modified_unix_nanos),
            ))
}

/// A successful native read can publish this separately from its checkpoint.
pub(in crate::snapshots) fn job_template_observation(
    candidate: &CandidateFile,
    acc: &SnapshotAccumulator,
) -> Option<JobTemplateObservation> {
    let [_, inode] = candidate.physical_identity?;
    let fact = if Fact::JobTemplate.present(acc) {
        Some(Enc::count_write(usize::MAX, |e| Fact::JobTemplate.put(acc, e)).ok()?)
    } else {
        if !acc.job_template_pending {
            return None;
        }
        None
    };
    Some(JobTemplateObservation {
        inode,
        birth_nanos: candidate.fingerprint_birth_nanos,
        fact,
    })
}

/// A reduction being dropped may be the only durable copy of the decision.
pub(in crate::snapshots) fn detached_job_template(
    head: &[u8],
    fact: Option<Vec<u8>>,
    pending: bool,
) -> anyhow::Result<Option<JobTemplateObservation>> {
    if fact.is_none() && !pending {
        return Ok(None);
    }
    let certificate =
        certified_certificate(head).map_err(|_| anyhow::anyhow!("state_v2_job_template_object"))?;
    Ok(Some(JobTemplateObservation {
        inode: certificate.inode,
        birth_nanos: certificate.birth_nanos,
        fact,
    }))
}

/// A separately published decision is newer than an unchanged checkpoint.
pub(super) fn restore_job_template_observation(
    index: &ScanIndex,
    key: &str,
    candidate: &CandidateFile,
    acc: &mut SnapshotAccumulator,
) -> anyhow::Result<bool> {
    let Some(job) = state_v2::load_job_template_observation(index, key)? else {
        return Ok(false);
    };
    if !same_file(candidate, job.inode, job.birth_nanos) {
        return Ok(false);
    }
    if let Some(fact) = job.fact {
        Fact::take(state_v2::JOB_TEMPLATE_PAGE, &fact, acc)
            .map_err(|_| anyhow::anyhow!("state_v2_job_template_fact"))?;
    } else {
        acc.job_template = None;
        acc.job_template_pending = true;
    }
    Ok(true)
}
