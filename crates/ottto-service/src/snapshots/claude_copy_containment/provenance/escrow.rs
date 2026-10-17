//! Move-only actual F1 -> C5 -> F3 input escrow. No cache admission or wakes.
use super::{record_f1_receipt, Marker, PendingCompletion};
use crate::heap_layout_bound;
use crate::snapshots::{
    sampled_scan::CopyReservation, ClaudeUsageAuthorityDisposition, ScanIndex, SourceScanResult,
    MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS, MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
};
use std::collections::BTreeSet;

struct Input {
    position: usize,
    binding: Marker,
    ids: BTreeSet<String>,
}
struct Escrow {
    inputs: Vec<Input>,
    // The source scope/generation and exact opened-binding carrier survive C5.
    completion: PendingCompletion,
    // Last: vector, moved sets, provenance/header all die before refund.
    reservation: CopyReservation,
}
/// Opaque and move-only. No positive cache, uniqueness, ACK or read API.
#[derive(Default)]
pub(crate) struct HeldNativeCompletion {
    escrow: Option<Escrow>,
}
impl ScanIndex {
    pub(crate) fn capture_copy_native_completion(
        &mut self,
        scan: &mut SourceScanResult,
        disposition: &ClaudeUsageAuthorityDisposition,
    ) -> HeldNativeCompletion {
        record_f1_receipt(0);
        #[cfg(test)]
        MOVEMENT_RECEIPT.with(|receipt| receipt.set((0, 0, 0)));
        let Some(completion) = self.take_source_provenance(scan) else {
            record_f1_receipt(0);
            return HeldNativeCompletion::default();
        };
        let result = (|| {
            // Borrowed predicate only: the optional refusal path must not
            // allocate a second anyhow error before existing finish handles it.
            if !disposition
                .copied_source_session_ids
                .preparation_available()
            {
                return None;
            }
            if disposition.copied_source_session_ids.is_empty() {
                record_f1_receipt(completion.visit_matches(scan, |_, _| {}));
                return None;
            }
            let owner = completion.owner()?;
            if !std::sync::Arc::ptr_eq(owner, self.required_copy_owner().ok()??) {
                return None;
            }
            let capacity = scan.snapshots.len().min(MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
            let vector_bytes = capacity.checked_mul(std::mem::size_of::<Input>())?;
            // Prepay output backing BEFORE allocation, while provenance and
            // all producer/index/returned-set credits remain live in the pool.
            let mut reservation = owner.reserve_copy_bytes(vector_bytes)?;
            let mut inputs = Vec::with_capacity(capacity);
            let mut bytes = vector_bytes;
            let mut membership_count = 0usize;
            let mut available = true;
            let matched = completion.visit_matches(scan, |position, marker| {
                let item = &scan.snapshots[position];
                if !available
                    || !disposition
                        .copied_source_session_ids
                        .contains(&item.source_session_id)
                    || item.claude_usage_request_ids.is_empty()
                {
                    return;
                }
                let next = (|| {
                    let count =
                        membership_count.checked_add(item.claude_usage_request_ids.len())?;
                    if count > MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS || inputs.len() == capacity {
                        return None;
                    }
                    // Existing parser graph will otherwise die at the filter.
                    // Pay this extension BEFORE any move, never reparse/clone.
                    let native_bytes = heap_layout_bound::completed_bound(
                        &item.claude_usage_request_ids,
                        super::super::required_budget::LIMIT,
                    )?;
                    let next_bytes = bytes.checked_add(native_bytes)?;
                    reservation.resize(next_bytes)?;
                    Some((count, next_bytes))
                })();
                let Some((count, next_bytes)) = next else {
                    available = false;
                    return;
                };
                membership_count = count;
                bytes = next_bytes;
                inputs.push(Input {
                    position,
                    binding: *marker,
                    ids: BTreeSet::new(),
                });
            });
            record_f1_receipt(matched);
            if !available || inputs.is_empty() {
                return None;
            }
            // All fallible validation/funding completed. Moving a BTreeSet
            // transfers its actual nodes/Strings without another allocation.
            #[cfg(test)]
            {
                let before = inputs
                    .first()
                    .and_then(|input| {
                        scan.snapshots[input.position]
                            .claude_usage_request_ids
                            .iter()
                            .next()
                    })
                    .map_or(0, |id| id.as_ptr() as usize);
                let (_, allocations) =
                    crate::retry_allocation_probe::measure(|| move_inputs(&mut inputs, scan));
                let after = inputs
                    .first()
                    .and_then(|input| input.ids.iter().next())
                    .map_or(0, |id| id.as_ptr() as usize);
                MOVEMENT_RECEIPT
                    .with(|receipt| receipt.set((before, after, allocations.allocations)));
            }
            #[cfg(not(test))]
            move_inputs(&mut inputs, scan);
            Some((inputs, reservation))
        })();
        match result {
            Some((inputs, reservation)) => HeldNativeCompletion {
                escrow: Some(Escrow {
                    inputs,
                    completion,
                    reservation,
                }),
            },
            None => HeldNativeCompletion::default(),
        }
    }
}
fn move_inputs(inputs: &mut [Input], scan: &mut SourceScanResult) {
    for input in inputs {
        input.ids = std::mem::take(&mut scan.snapshots[input.position].claude_usage_request_ids);
    }
}
#[cfg(test)]
thread_local! { static MOVEMENT_RECEIPT: std::cell::Cell<(usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0)) }; }
#[cfg(test)]
impl HeldNativeCompletion {
    pub(crate) fn movement_for_test() -> (usize, usize, usize) {
        MOVEMENT_RECEIPT.with(std::cell::Cell::get)
    }
    pub(crate) fn first_pointer_for_test(&self) -> Option<*const u8> {
        self.escrow
            .as_ref()?
            .inputs
            .first()?
            .ids
            .iter()
            .next()
            .map(|id| id.as_ptr())
    }
    pub(crate) fn count_for_test(&self) -> usize {
        self.escrow.as_ref().map_or(0, |e| e.inputs.len())
    }
    pub(crate) fn bound_for_test(
        &self,
        root: &std::path::Path,
        path: &str,
        revision: &str,
        session: &str,
    ) -> bool {
        let Some(root) = root.to_str() else {
            return false;
        };
        self.escrow.as_ref().is_some_and(|escrow| {
            escrow.inputs.iter().any(|input| {
                input.binding.root == super::hash("copy_native_root:v1", &[root.as_bytes()])
                    && input.binding.path == super::hash("copy_native_path:v1", &[path.as_bytes()])
                    && input.binding.revision
                        == super::hash("copy_native_revision:v1", &[revision.as_bytes()])
                    && input.binding.session
                        == super::hash("copy_native_session:v1", &[session.as_bytes()])
            })
        })
    }
    pub(crate) fn credit_for_test(&self) -> usize {
        self.escrow.as_ref().map_or(0, |e| e.reservation.bytes())
    }
}
