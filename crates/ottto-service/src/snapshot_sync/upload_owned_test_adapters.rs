//! Owned callbacks for existing upload fixtures; production borrows.
use super::*;

pub(super) fn bootstrap_cache_heads_with_budget(
    probes: &[SnapshotItem],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    inplace_retry: &mut InplaceRetryBudget,
    mut upload: impl FnMut(
        Vec<SnapshotItem>,
        bool,
    ) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    persist: impl FnMut(&mut SnapshotUploadProgress) -> Result<()>,
) -> Result<usize> {
    super::bootstrap_cache_heads_with_budget(
        probes,
        poison_scope,
        progress,
        inplace_retry,
        |items, enforce| upload(items.iter().copied().cloned().collect(), enforce),
        persist,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "owned callback adapter for existing upload fixtures"
)]
pub(super) fn attempt_snapshot_page<T, Fingerprint, BodyWitness, SessionId, Upload, Persist>(
    items: &[T],
    indices: &[usize],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: &Fingerprint,
    body_witness: &BodyWitness,
    session_id: &SessionId,
    upload: &mut Upload,
    persist: &mut Persist,
) -> Result<SnapshotPageOutcome>
where
    T: Clone + Serialize,
    Fingerprint: Fn(&T) -> &str,
    BodyWitness: Fn(&T) -> String,
    SessionId: Fn(&T) -> Option<&str>,
    Upload: FnMut(Vec<T>) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    super::attempt_snapshot_page(
        items,
        indices,
        poison_scope,
        progress,
        accepted,
        fingerprint,
        body_witness,
        session_id,
        &mut |batch| upload(batch.iter().copied().cloned().collect()),
        persist,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "owned callback adapter for existing upload fixtures"
)]
pub(super) fn upload_resumable_batches_with_literal_families<
    T,
    Fingerprint,
    BodyWitness,
    SessionId,
    BatchClass,
    LiteralFamily,
    Upload,
    Persist,
>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    body_witness: BodyWitness,
    session_id: SessionId,
    batch_class: BatchClass,
    literal_family: LiteralFamily,
    inplace_retry: &mut InplaceRetryBudget,
    mut upload: Upload,
    persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Clone + Serialize,
    Fingerprint: Fn(&T) -> &str,
    BodyWitness: Fn(&T) -> String,
    SessionId: Fn(&T) -> Option<&str>,
    BatchClass: Fn(&T) -> u8,
    LiteralFamily: Fn(&T) -> Option<&str>,
    Upload: FnMut(Vec<T>) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    super::upload_resumable_batches_with_literal_families(
        items,
        poison_scope,
        progress,
        accepted,
        fingerprint,
        body_witness,
        session_id,
        batch_class,
        literal_family,
        inplace_retry,
        |batch| upload(batch.iter().copied().cloned().collect()),
        persist,
    )
}
