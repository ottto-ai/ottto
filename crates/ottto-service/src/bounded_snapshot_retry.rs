//! Native complete-page retry preparation. No parser borrow, alternate ACK
//! writer, persisted body, token or report lease survives a turn.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::snapshot_retry::RetryBudget;

/// Accepted E9-2 requested-layout evidence (Lead A ruling, 2026-10-28):
/// 4H for outgoing clone, selected checkpoint/restoration, ACK maps and JSON
/// comparisons; 4 MiB auxiliary decode (8192 nodes, capped 128 KiB input);
/// 4 MiB encoded index/request/response copies, gzip and ACK response growth;
/// 8 MiB transport/TLS workspace. Admission enforces 4H + 16 MiB <= 20 MiB,
/// hence H <= 1 MiB before copies. The partition model plus native peak receipts
/// at the largest admitted pages is the accepted evidence, not a universal
/// decoder/TLS or RSS proof. The retained owner is charged separately below.
/// Initial checkpoint validation streams a comparison, with no native decode
/// or serialized index copies; native ACK/selected-index bounded decoders stay.
/// Fresh binding/file-secret loads are capped at 64 KiB before reading.
/// Keychain loads belong to the shared ordinary-path resource domain and are
/// not charged to the retry reserve. Allocator slack and process RSS are separate.
const SEND_BUDGET: usize = 20 * 1024 * 1024;
const SEND_FIXED: usize = 16 * 1024 * 1024;
const RETAINED_BUDGET: usize =
    crate::source_rotation::OVERLAP_BUDGET - crate::source_rotation::PARKED_BUDGET - SEND_BUDGET;

fn turn_peak_bound(retained: usize) -> Option<usize> {
    retained
        .checked_mul(4)?
        .checked_add(SEND_FIXED)
        .filter(|peak| *peak <= SEND_BUDGET)
}

// Compare exactly the native writer's encoding, without decoding competing
// state. A differently formatted checkpoint safely returns to ordinary work.
pub(super) fn checkpoint_matches<T: Serialize>(
    path: &Path,
    expected: &T,
    pretty: bool,
) -> Result<bool> {
    struct Compare<'a>(&'a [u8]);
    impl std::io::Write for Compare<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.0.starts_with(bytes) {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "checkpoint changed",
                ));
            }
            self.0 = &self.0[bytes.len()..];
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let bytes = crate::snapshot_retry::read_state(path, crate::snapshot_retry::RESPONSE_BYTES)?;
    crate::snapshot_retry::state_shape(&bytes)?;
    let mut compare = Compare(&bytes);
    let result = if pretty {
        serde_json::to_writer_pretty(&mut compare, expected)
    } else {
        serde_json::to_writer(&mut compare, expected)
    };
    if result.is_ok() && compare.0.is_empty() {
        return Ok(true);
    }
    // The native index writer uses pretty JSON when decode holds exist.
    // On mismatch serialize a second time for that alternate native encoding.
    // Both sequential passes compare against the same RESPONSE_BYTES-capped
    // buffer, with no decode or serialized output copy; reserves are not doubled.
    compare.0 = &bytes;
    let result = if pretty {
        serde_json::to_writer(&mut compare, expected)
    } else {
        serde_json::to_writer_pretty(&mut compare, expected)
    };
    Ok(result.is_ok() && compare.0.is_empty())
}

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
        turn_peak_bound(counter.bytes)?;
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
        if turn_peak_bound(counter.bytes).is_none() {
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
    #[cfg(test)]
    pub(super) fn peak_bound(&self) -> usize {
        turn_peak_bound(self.bound).expect("admitted requested-layout peak")
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
        // All heap admission precedes auxiliary reads/decodes. Compare against
        // already bounded native state; never decode a changed checkpoint first.
        anyhow::ensure!(
            turn_peak_bound(self.bound).is_some(),
            "retry peak exceeds budget"
        );
        if !checkpoint_matches(&self.progress_path, &self.progress, true)?
            || !checkpoint_matches(&self.index_path, &self.baseline, false)?
        {
            return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "checkpoint changed before optional snapshot retry",
            }));
        }
        Ok(())
    }

    /// Called only by the existing owner at an admitted collection boundary.
    /// `validate` must establish fresh account/device/destination/stop plus
    /// complete native dependency and policy authority.
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
                &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
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
            // Retained-body retries carry correction debt unchanged; no new
            // scan facts can qualify an empty-member completion here.
            None,
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
