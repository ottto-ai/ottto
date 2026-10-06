//! Native complete-page retry preparation. No parser borrow, alternate ACK
//! writer, persisted body, token or report lease survives a turn.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::snapshot_retry::RetryBudget;

/// This gate is intentionally closed in production while the complete live
/// dependency/policy witness and wake integration receive activation review.
/// It is not an environment option or a new scheduler.
const ACTIVATED: bool = false;
// A single shared overlap budget:8MiB parked scans +4MiB retained native
// context +20MiB reserved send/checkpoint allowance. The latter remains an
// activation-review bound, not a physical-memory claim from loopback evidence.
const RETAINED_BUDGET: usize = crate::source_rotation::OVERLAP_BUDGET
    - crate::source_rotation::PARKED_BUDGET
    - 20 * 1024 * 1024;

struct BodyProof {
    fingerprint: [u8; 64],
    body: [u8; 64],
}

pub(super) struct PreparedRetry {
    source: SnapshotSource,
    machine_id: String,
    policy: SnapshotUploadPolicy,
    authority: [u8; 32],
    items: Vec<SnapshotItem>,
    proof: Vec<BodyProof>,
    working: ScanIndex,
    baseline: ScanIndex,
    progress: SnapshotUploadProgress,
    index_path: PathBuf,
    progress_path: PathBuf,
    pub(super) budget: RetryBudget,
    bound: usize,
    live: Option<super::live_snapshot_retry::LiveAuthority>,
}
impl PreparedRetry {
    /// Admission precedes every deep copy. All native ledger/index/context
    /// storage shares the cap; no unaccounted 128KiB context is implied.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture(
        source: SnapshotSource,
        machine_id: &str,
        policy: SnapshotUploadPolicy,
        authority: [u8; 32],
        items: &[SnapshotItem],
        working: &ScanIndex,
        baseline: &ScanIndex,
        progress: &SnapshotUploadProgress,
        index_path: &Path,
        progress_path: &Path,
        now: Instant,
        delay: Duration,
        allowance: usize,
    ) -> Option<Self> {
        if !crate::heap_layout_bound::layout_supported()
            || working.generation != baseline.generation
        {
            return None;
        }
        for path in [index_path, progress_path] {
            if std::fs::metadata(path).ok()?.len() > crate::snapshot_retry::RESPONSE_BYTES as u64 {
                return None;
            }
        }
        let cap = allowance
            .min(RETAINED_BUDGET)
            .min(crate::retry_retention_bound::HEAP_CAP);
        let page = crate::retry_retention_bound::page_bound(items, cap)?;
        // Count escaped JSON before any retained-body deep copy. The actual
        // wire serializer has its own cap including semantic envelopes.
        if !crate::snapshot_retry::json_fits(items, crate::snapshot_retry::REQUEST_BYTES / 2)
            || !crate::snapshot_retry::json_fits(working, crate::snapshot_retry::RESPONSE_BYTES)
            || !crate::snapshot_retry::json_fits(baseline, crate::snapshot_retry::RESPONSE_BYTES)
            || !crate::snapshot_retry::json_fits(progress, crate::snapshot_retry::RESPONSE_BYTES)
        {
            return None;
        }
        let mut counter = Counter::new(cap);
        counter.add(page)?;
        counter.add(std::mem::size_of::<Self>())?;
        working.heap_bound(&mut counter)?;
        baseline.heap_bound(&mut counter)?;
        progress.heap_bound(&mut counter)?;
        counter.add(index_path.as_os_str().len())?;
        counter.add(progress_path.as_os_str().len())?;
        counter.add(machine_id.len())?;
        let proof_size = items.len().checked_mul(std::mem::size_of::<BodyProof>())?;
        // The page bound reserves this fixed proof storage. It is enforced,
        // rather than adding another independent reservation.
        if proof_size > crate::retry_retention_bound::PROOF_RESERVE {
            return None;
        }
        let budget = RetryBudget::after_shed(now, delay)?;
        let mut copied = Vec::with_capacity(items.len());
        let mut proof = Vec::with_capacity(items.len());
        for item in items {
            proof.push(BodyProof {
                fingerprint: item.snapshot_fingerprint.as_bytes().try_into().ok()?,
                body: snapshot_upload_body_witness(item)
                    .as_bytes()
                    .try_into()
                    .ok()?,
            });
            copied.push(retry_ordinary_owned(item)?);
        }
        Some(Self {
            source,
            machine_id: machine_id.to_owned(),
            policy,
            authority,
            items: copied,
            proof,
            working: working.clone(),
            baseline: baseline.clone(),
            progress: progress.clone(),
            index_path: index_path.to_owned(),
            progress_path: progress_path.to_owned(),
            budget,
            bound: counter.bytes,
            live: None,
        })
    }

    pub(super) fn attach_live_authority(
        &mut self,
        live: super::live_snapshot_retry::LiveAuthority,
        allowance: usize,
    ) -> bool {
        let mut counter = Counter::new(allowance.min(RETAINED_BUDGET));
        if counter.add(self.bound).is_none() || live.heap_bound(&mut counter).is_none() {
            return false;
        }
        self.bound = counter.bytes;
        self.live = Some(live);
        true
    }
    pub(super) fn source(&self) -> SnapshotSource {
        self.source
    }
    pub(super) fn authority(&self) -> [u8; 32] {
        self.authority
    }
    pub(super) fn take_live_authority(
        &mut self,
    ) -> Result<super::live_snapshot_retry::LiveAuthority> {
        self.live
            .take()
            .ok_or_else(|| anyhow!("optional snapshot retry lacks live authority"))
    }
    pub(super) fn restore_live_authority(
        &mut self,
        live: super::live_snapshot_retry::LiveAuthority,
    ) {
        self.live = Some(live);
    }

    pub(super) fn turn_live(
        &mut self,
        client: &SnapshotApiClient,
        device: &LocalDeviceBinding,
        secret: &str,
        policy: &[u8; 32],
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<SnapshotPageOutcome> {
        // The complete live input seal authorizes these unchanged owned bodies.
        // No parse or second body copy is needed to establish a retry turn.
        self.validate_body(&self.items, &self.authority)?;
        self.turn_inner(client, device, secret, Some(policy), validate)
    }

    #[cfg(test)]
    pub(super) fn bound(&self) -> usize {
        self.bound
    }
    fn validate_body(&self, current: &[SnapshotItem], authority: &[u8; 32]) -> Result<()> {
        if authority != &self.authority
            || !self.proof.iter().all(|proof| {
                current.iter().any(|item| {
                    item.snapshot_fingerprint.as_bytes() == proof.fingerprint
                        && crate::retry_retention_bound::page_bound(
                            std::slice::from_ref(item),
                            RETAINED_BUDGET,
                        )
                        .is_some()
                        && crate::snapshots::snapshot_fingerprint(self.source, item).as_bytes()
                            == proof.fingerprint
                        && snapshot_upload_body_witness(item).as_bytes() == proof.body
                })
            })
        {
            return Err(anyhow!("prepared retry authority or body changed"));
        }
        Ok(())
    }

    fn validate_native_checkpoint(&self) -> Result<()> {
        let _lock = SnapshotProgressLock::acquire(&self.progress_path)?;
        let bytes = crate::snapshot_retry::read_state(
            &self.progress_path,
            crate::snapshot_retry::RESPONSE_BYTES,
        )?;
        let mut durable: SnapshotUploadProgress = crate::snapshot_retry::decode_state(&bytes)?;
        durable.active_quarantine_witness = self.progress.active_quarantine_witness.clone();
        durable.active_quarantine_retries = self.progress.active_quarantine_retries.clone();
        if crate::heap_layout_bound::bound(&durable, RETAINED_BUDGET).is_none()
            || durable != self.progress
        {
            return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "progress changed before optional snapshot retry",
            }));
        }
        let bytes = crate::snapshot_retry::read_state(
            &self.index_path,
            crate::snapshot_retry::RESPONSE_BYTES,
        )?;
        let current: ScanIndex = crate::snapshot_retry::decode_state(&bytes)?;
        if crate::heap_layout_bound::bound(&current, RETAINED_BUDGET).is_none()
            || serde_json::to_vec(&current)? != serde_json::to_vec(&self.baseline)?
        {
            return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "index changed before optional snapshot retry",
            }));
        }
        Ok(())
    }

    /// Called only by the existing owner at an admitted collection boundary.
    /// `validate` must establish fresh account/device/destination/stop plus
    /// complete native dependency and policy authority; activation stays off
    /// until that actual source-owned hook is reviewed, not supplied by a flag.
    pub(super) fn turn(
        &mut self,
        client: &SnapshotApiClient,
        device: &LocalDeviceBinding,
        device_secret: &str,
        current_items: &[SnapshotItem],
        authority: &[u8; 32],
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<SnapshotPageOutcome> {
        self.validate_body(current_items, authority)?;
        self.turn_inner(client, device, device_secret, None, validate)
    }

    fn turn_inner(
        &mut self,
        client: &SnapshotApiClient,
        device: &LocalDeviceBinding,
        device_secret: &str,
        live_policy: Option<&[u8; 32]>,
        validate: &mut dyn FnMut() -> Result<()>,
    ) -> Result<SnapshotPageOutcome> {
        self.validate_native_checkpoint().map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "validate optional snapshot checkpoint",
            })
        })?;
        if device.machine_id.as_deref() != Some(self.machine_id.as_str())
            || !enabled_snapshot_sources(device).contains(&self.source)
        {
            return Err(anyhow!("optional snapshot retry source grant changed"));
        }
        validate()?;
        self.budget.enter(Instant::now())?;
        let pending = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                !self.progress.contains_body(
                    &item.snapshot_fingerprint,
                    &snapshot_upload_body_witness(item),
                )
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let source = self.source;
        let policy = self.policy;
        let machine_id = &self.machine_id;
        let budget = &mut self.budget;
        let outcome = if pending.is_empty() {
            SnapshotPageOutcome::Settled { conflicted: 0 }
        } else {
            attempt_snapshot_page(
                &self.items,
                &pending,
                source.api_slug(),
                &mut self.progress,
                &mut 0,
                &|item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
                &snapshot_upload_body_witness,
                &mut |snapshots| {
                    let lease = crate::client_report::lease();
                    let request = SnapshotBatchRequest {
                        schema_version: SNAPSHOT_SCHEMA_VERSION,
                        source: source.api_slug().into(),
                        machine_id: machine_id.clone(),
                        collector_version: Some(collector_version()),
                        snapshots,
                        upload_policy: policy,
                        client_report: lease.report().clone(),
                    };
                    validate_snapshot_batch_request(&request).map_err(|reason| {
                        anyhow::Error::new(SnapshotBatchPreflightRejected { reason })
                    })?;
                    anyhow::ensure!(
                        crate::snapshot_retry::json_fits(
                            &request,
                            crate::snapshot_retry::REQUEST_BYTES
                        ),
                        "optional snapshot wire request exceeds admission limit"
                    );
                    let mut token = client.issue_relay_token_bounded(
                        device,
                        device_secret,
                        source,
                        budget,
                        validate,
                    )?;
                    if let Some(expected) = live_policy {
                        let mut hint =
                            client.get_activity_hint_bounded(&token, budget, validate)?;
                        anyhow::ensure!(
                            super::live_snapshot_retry::fresh_policy_seal(&mut hint).as_ref()
                                == Some(expected),
                            "optional snapshot policy changed"
                        );
                    }
                    let response = match client
                        .upload_batch_bounded(&token, &request, false, budget, validate)
                    {
                        Err(error)
                            if error.downcast_ref::<BatchAuthorizationRejected>().is_some() =>
                        {
                            // No old token or report is held across a wait. Auth replay
                            // uses this same turn and the same remaining POST counter.
                            token = client.issue_relay_token_bounded(
                                device,
                                device_secret,
                                source,
                                budget,
                                validate,
                            )?;
                            if let Some(expected) = live_policy {
                                let mut hint =
                                    client.get_activity_hint_bounded(&token, budget, validate)?;
                                anyhow::ensure!(
                                    super::live_snapshot_retry::fresh_policy_seal(&mut hint)
                                        .as_ref()
                                        == Some(expected),
                                    "optional snapshot policy changed"
                                );
                            }
                            client
                                .upload_batch_bounded(&token, &request, false, budget, validate)?
                        }
                        result => result?,
                    };
                    response.validate_entity_ack(&request)?;
                    lease.commit();
                    Ok(response)
                },
                &mut |progress| {
                    progress.save_with_read_limit(
                        &self.progress_path,
                        Some(crate::snapshot_retry::RESPONSE_BYTES),
                    )
                },
            )?
        };
        if matches!(outcome, SnapshotPageOutcome::Disabled(_)) {
            return Ok(outcome);
        }
        // Exact ACK is durable even if authority expires/changes after response.
        // Only publication needs the following fresh guard; it never rolls ACK
        // evidence back or adopts a competitor's disk generation.
        budget.remaining(Instant::now())?;
        validate()?;
        let checkpoint = checkpoint_partial_snapshot_index_with_read_limit(
            &self.working,
            &self.baseline,
            &self.progress,
            &self.items,
            &BTreeSet::new(),
            &self.index_path,
            &self.progress_path,
            validate,
            Some(crate::snapshot_retry::RESPONSE_BYTES),
        )?;
        self.working.generation = checkpoint.generation;
        self.working.mark_bounded_sweep_unsettled();
        self.baseline = checkpoint;
        Ok(outcome)
    }
}

/// Activation review is intentionally still closed. The daemon now owns the
/// live plumbing, but its production constructor cannot capture or send.
pub(super) fn production_activation_reviewed() -> bool {
    ACTIVATED
}

/// Complete bodies share one bounded owner reservation. One source slot and
/// one optional turn per collection boundary prevent a retained upload from
/// monopolising parser progress. The cursor survives a shed; its POST and
/// lifetime allowance belongs to the body, never to the wake.
#[derive(Default)]
pub(super) struct RetryOwner {
    slots: [Option<PreparedRetry>; 3],
    next: usize,
}
fn source_slot(source: SnapshotSource) -> usize {
    match source {
        SnapshotSource::Codex => 0,
        SnapshotSource::ClaudeCode => 1,
        SnapshotSource::Pi => 2,
    }
}
impl RetryOwner {
    pub(super) fn allowance(&self) -> usize {
        RETAINED_BUDGET.saturating_sub(
            std::mem::size_of::<Self>()
                + self.slots.iter().flatten().map(|s| s.bound).sum::<usize>(),
        )
    }
    pub(super) fn admit(&mut self, page: PreparedRetry) -> bool {
        let index = source_slot(page.source);
        if self.slots[index].is_some() || page.bound > self.allowance() {
            return false;
        }
        self.slots[index] = Some(page);
        true
    }
    pub(super) fn clear(&mut self) {
        self.slots = [None, None, None];
    }
    pub(super) fn wake_before(&self, ordinary_deadline: Instant) -> Instant {
        self.slots
            .iter()
            .flatten()
            .fold(ordinary_deadline, |deadline, page| {
                page.budget.wake_before(deadline)
            })
    }
    pub(super) fn boundary(
        &mut self,
        busy: impl Iterator<Item = SnapshotSource>,
        now: Instant,
        mut send: impl FnMut(&mut PreparedRetry) -> Result<SnapshotPageOutcome>,
    ) {
        let mut blocked = [false; 3];
        for source in busy {
            blocked[source_slot(source)] = true;
        }
        for offset in 0..3 {
            let index = (self.next + offset) % 3;
            let Some(page) = self.slots[index].as_mut() else {
                continue;
            };
            if now >= page.budget.expires() || page.budget.posts_left() == 0 {
                self.slots[index] = None;
                continue;
            }
            if blocked[index] || now < page.budget.due() {
                continue;
            }
            self.next = (index + 1) % 3;
            match send(page) {
                Err(error) if error.downcast_ref::<UploadShed>().is_some() => {
                    let retry_after = error
                        .downcast_ref::<UploadShed>()
                        .expect("typed shed")
                        .retry_after;
                    let delay = note_shed_and_backoff(page.source, retry_after);
                    defer_source_uploads(page.source, delay);
                    if !page.budget.defer(Instant::now(), delay) {
                        self.slots[index] = None;
                    }
                }
                // Settlement, disabled, conflict, cancellation, competing state
                // and ambiguous transport all recover through ordinary native
                // preparation. No alternate retry classification or ACK writer.
                _ => self.slots[index] = None,
            }
            break;
        }
    }
}
