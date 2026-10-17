//! Private single-observation owner. Source checkpoint only: the scan producer
//! still uses its old inactive seam until control/transport owners are closed.
//! API callers own their returned protocol values; arbitrary caller clones are
//! outside scan/cache accounting. No public Clone/schema or global cap changes.
use super::pipeline::CopyContainmentStatus;
use super::required_budget::LIMIT;
use super::status_costing::{closed_status_costs, projection_slot_peak};
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::snapshots::sampled_scan::{CopyReservation, SharedCache};
use ottto_protocol::{LocalHealthAuthority, LocalHealthEventV1};
use serde::Serialize;
use std::fmt::Write as _;
use std::io;
use std::mem::size_of;
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const EVENT_TYPE: &str = crate::snapshot_sync::COPY_CONTAINMENT_EVENT_TYPE;
const SCHEMA: &str = "local_health_event.v1";
const PREFIX: &str = "evt_claude_copy_containment_";
const MESSAGE: &str =
    "Claude copy containment source checkpoint; held usage remains unresolved, never zero.";
const TIMESTAMP_BYTES: usize = 40;

#[derive(Debug)]
struct Record {
    observation: CopyContainmentStatus,
    basis: &'static str,
    sequence: u64,
    timestamp: [u8; TIMESTAMP_BYTES],
    timestamp_len: usize,
}
impl Record {
    fn new(observation: CopyContainmentStatus, basis: &'static str, sequence: u64) -> Option<Self> {
        if !matches!(
            basis,
            "uncommitted_scan_observation" | "durable_partial_selection" | "durable_selected_index"
        ) || sequence == 0
        {
            return None;
        }
        // Exhaustive HeapLayoutBound implementations on the two closed typed
        // structs make a future owned field a refused shape, not an unpaid box.
        let mut inline = Counter::new(0);
        observation.heap_bound(&mut inline)?;
        let mut timestamp = [0; TIMESTAMP_BYTES];
        let timestamp_len = {
            let mut writer = TimestampWriter {
                bytes: &mut timestamp,
                written: 0,
            };
            OffsetDateTime::now_utc()
                .format_into(&mut writer, &Rfc3339)
                .ok()?;
            writer.written
        };
        std::str::from_utf8(&timestamp[..timestamp_len]).ok()?;
        Some(Self {
            observation,
            basis,
            sequence,
            timestamp,
            timestamp_len,
        })
    }
    fn observed_at(&self) -> &str {
        // Rfc3339 writes UTF8; treat any unexpected representation as UNKNOWN
        // before materialization rather than allocating an error message.
        std::str::from_utf8(&self.timestamp[..self.timestamp_len])
            .expect("validated stack timestamp")
    }
    fn payload(&self) -> Payload<'_> {
        Payload {
            kind: "claude_copy_containment",
            current: true,
            basis: self.basis,
            observation: &self.observation,
            message: MESSAGE,
        }
    }
}
struct TimestampWriter<'a> {
    bytes: &'a mut [u8],
    written: usize,
}
impl io::Write for TimestampWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .written
            .checked_add(bytes.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(io::ErrorKind::WriteZero)?;
        self.bytes[self.written..end].copy_from_slice(bytes);
        self.written = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Serialize)]
struct Payload<'a> {
    kind: &'static str,
    current: bool,
    basis: &'static str,
    observation: &'a CopyContainmentStatus,
    message: &'static str,
}

#[derive(Debug)]
struct Slot {
    // Field order is intentional: free Box storage BEFORE returning credit.
    value: Box<Record>,
    _credit: CopyReservation,
}
#[derive(Debug, Default)]
pub(crate) struct CopyObservationState {
    slot: Option<Slot>,
    // Retain the last successful id after disable/drop; no event history.
    last_sequence: u64,
}
impl CopyObservationState {
    pub(crate) fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
    pub(crate) fn clear(&mut self) {
        self.slot = None;
    }
    /// Equal payloads preserve time/id/sequence. Refusal leaves the previous
    /// observation and sequence intact; required debt lives in ScanIndex.
    /// No ordinary scan producer calls this source-only checkpoint yet.
    pub(crate) fn replace(
        &mut self,
        owner: &Arc<SharedCache>,
        observation: CopyContainmentStatus,
        basis: &'static str,
        sequence: u64,
    ) -> Option<bool> {
        if !owner.copy_containment_required() {
            self.clear();
            return Some(false);
        }
        if self
            .slot
            .as_ref()
            .is_some_and(|slot| slot.value.basis == basis && slot.value.observation == observation)
        {
            return Some(false);
        }
        if sequence <= self.last_sequence {
            return None;
        }
        let record = Record::new(observation, basis, sequence)?;
        if let Some(slot) = &mut self.slot {
            if !Arc::ptr_eq(owner, slot._credit.owner()) {
                return None;
            }
            // No owned replacement graph: one fixed typed allocation reused.
            *slot.value = record;
        } else {
            let credit = owner.reserve_copy_bytes(size_of::<Record>())?;
            self.slot = Some(Slot {
                value: Box::new(record),
                _credit: credit,
            });
        }
        self.last_sequence = sequence;
        Some(true)
    }
    /// Initial private status assembly only. The returned lease covers two
    /// materialized event copies + full Vec threshold overlap until this
    /// operation transfers the response. Later internal control/transport
    /// operations require their own scope and are deliberately not wired here.
    pub(crate) fn prepay_projection<'a>(
        &'a self,
        machine_id: &'a str,
        existing_events: usize,
    ) -> Option<CopyObservationProjection<'a>> {
        let slot = self.slot.as_ref()?;
        let costs = closed_status_costs(&slot.value.payload(), existing_events, existing_events)?;
        let id_capacity = PREFIX.len().checked_add(20)?;
        let strings = id_capacity
            .checked_add(SCHEMA.len())?
            .checked_add(EVENT_TYPE.len())?
            .checked_add(machine_id.len())?
            .checked_add(slot.value.observed_at().len())?;
        let bytes = costs
            .two_projection_payloads
            .checked_add(strings.checked_mul(2)?)?
            .checked_add(super::status_costing::runtime_sequence_string_peak(4)?)?
            .checked_add(projection_slot_peak(existing_events)?)?;
        if bytes > LIMIT {
            return None;
        }
        let credit = slot._credit.owner().reserve_copy_bytes(bytes)?;
        Some(CopyObservationProjection {
            record: &slot.value,
            machine_id,
            existing_events,
            _credit: credit,
        })
    }
}
#[derive(Debug)]
pub(crate) struct CopyObservationProjection<'a> {
    record: &'a Record,
    machine_id: &'a str,
    existing_events: usize,
    _credit: CopyReservation,
}
impl CopyObservationProjection<'_> {
    pub(crate) fn append(
        self,
        events: &mut Vec<LocalHealthEventV1>,
    ) -> Option<CopyObservationOutput> {
        // The borrowed record and machine bind this permit through projection.
        // A different vector shape or an old producer event is not covered.
        if events.len() != self.existing_events
            || events.capacity() != self.existing_events
            || events.iter().any(|event| event.event_type == EVENT_TYPE)
        {
            return None;
        }
        let record = self.record;
        let machine_id = self.machine_id;
        let mut event_id = String::with_capacity(PREFIX.len().checked_add(20)?);
        write!(event_id, "{PREFIX}{}", record.sequence).ok()?;
        let event = LocalHealthEventV1 {
            event_id,
            event_schema_version: SCHEMA.to_owned(),
            event_type: EVENT_TYPE.to_owned(),
            machine_id: machine_id.to_owned(),
            observed_at: record.observed_at().to_owned(),
            sequence: record.sequence,
            authority: LocalHealthAuthority::Runtime,
            source_id: None,
            action_id: None,
            payload: serde_json::to_value(record.payload()).ok()?,
        };
        // Preserve unrelated event order, including events emitted after this
        // observation. Reads never write sequence or mint a replacement id.
        let position = events
            .iter()
            .position(|event| event.sequence > record.sequence)
            .unwrap_or(events.len());
        events.insert(position, event);
        Some(CopyObservationOutput {
            _credit: self._credit,
        })
    }
}
/// Linear append consumes its permit. This guard keeps credit through the
/// single internal canonical projection and cannot materialize another event.
#[derive(Debug)]
pub(crate) struct CopyObservationOutput {
    _credit: CopyReservation,
}

/// Private lexical guard for the control Status arm only. Optional projection
/// failure removes only the local observation; its required scan ledger and
/// private persistent observation are never modified or declared settled.
/// Other control consumers remain separately unqualified before activation.
pub(crate) fn prepay_control_status(
    owner: &Arc<SharedCache>,
    status: &mut ottto_protocol::DaemonStatus,
) -> Option<CopyObservationOutput> {
    if !status
        .local_health_events
        .iter()
        .any(|event| event.event_type == EVENT_TYPE)
    {
        return None;
    }
    let credit = super::status_costing::control_status_peak(status)
        .and_then(|bytes| owner.reserve_copy_bytes(bytes));
    match credit {
        Some(credit) => Some(CopyObservationOutput { _credit: credit }),
        None => {
            status
                .local_health_events
                .retain(|event| event.event_type != EVENT_TYPE);
            // Content-free unavailable observation is not a complete status of
            // held debt. Do not report zero/no holds or clear persistent debt.
            eprintln!("local copied-request status observation unavailable");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::ScanIndex;
    use std::io::Write as _;

    #[test]
    fn copy_containment_typed_status_stack_record_and_invalid_basis_allocate_nothing() {
        let observation = ScanIndex::default().copy_containment_status(Some(100));
        let (_, actual) = crate::retry_allocation_probe::measure(|| {
            let record = Record::new(observation.clone(), "durable_selected_index", 17).unwrap();
            assert_eq!(record.sequence, 17);
            assert!(!record.observed_at().is_empty());
            assert!(Record::new(observation, "unknown basis", 18).is_none());
        });
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.requested_live, 0);
        writeln!(std::io::stderr().lock(), "copy_containment_typed_status_stack: fixed_timestamp=true exhaustive_observation_no_owned_fields=true allocation_calls=0 unknown_basis_refused=true").unwrap();
    }

    #[test]
    fn copy_containment_typed_status_slot_prepays_once_reuses_box_and_retires_after_data() {
        let owner = Arc::new(SharedCache::default());
        let observation = ScanIndex::default().copy_containment_status(Some(100));
        let mut state = CopyObservationState::default();
        assert_eq!(
            state.replace(&owner, observation.clone(), "durable_selected_index", 1),
            Some(false)
        );
        assert!(state.slot.is_none());
        owner.require_copy_containment_for_test();
        let (result, actual) = crate::retry_allocation_probe::measure(|| {
            state.replace(&owner, observation.clone(), "durable_selected_index", 1)
        });
        if !super::super::required_decode::profile_supported() {
            assert_eq!(result, None);
            assert_eq!(actual.allocations, 0);
            assert_eq!(state.last_sequence(), 0);
            assert!(state.slot.is_none());
            writeln!(std::io::stderr().lock(), "copy_containment_typed_status_slot: layout_supported=false unsupported_before_box=true positive_slot_reuse_and_retirement=UNEXECUTED").unwrap();
            return;
        }
        assert_eq!(result, Some(true));
        let pointer = state.slot.as_ref().unwrap().value.as_ref() as *const Record;
        let reserved = owner.reserved_copy_bytes_for_test().unwrap();
        assert_eq!(reserved, size_of::<Record>());
        assert_eq!(actual.requested_live, size_of::<Record>() as isize);
        let (_, updates) = crate::retry_allocation_probe::measure(|| {
            assert_eq!(
                state.replace(&owner, observation.clone(), "durable_selected_index", 2),
                Some(false)
            );
            assert_eq!(
                state.last_sequence(),
                1,
                "equal payload never advances time/id"
            );
            assert_eq!(
                state.replace(&owner, observation.clone(), "durable_partial_selection", 2),
                Some(true)
            );
            assert_eq!(state.replace(&owner, observation, "unknown basis", 3), None);
        });
        assert_eq!(updates.allocations, 0);
        assert_eq!(state.last_sequence(), 2);
        assert_eq!(
            state.slot.as_ref().unwrap().value.as_ref() as *const Record,
            pointer
        );
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(reserved));
        state.clear();
        assert_eq!(
            state.last_sequence(),
            2,
            "clearing cannot reuse an old sequence"
        );
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(0));
        writeln!(std::io::stderr().lock(), "copy_containment_typed_status_slot: layout_supported=true persistent_requested_bytes={reserved} one_box=true in_place_updates_no_alloc=true equal_payload_id_stable=true invalid_replacement_keeps_old=true data_freed_before_credit=true").unwrap();
    }

    #[test]
    fn copy_containment_typed_status_projection_refusal_keeps_required_debt_and_private_record() {
        let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
        value["claude_copy_holds"] = serde_json::json!({"synthetic-held-path": {
            "revision": {"version": 1, "reason": "copied_overlap_unproven",
                "source_revision": "a".repeat(64), "comparison_context": "b".repeat(64),
                "first_observed_unix_seconds": null}, "peers": ["c".repeat(64)]
        }});
        let index: ScanIndex = serde_json::from_value(value).unwrap();
        let debt_before = serde_json::to_vec(&index).unwrap();
        let owner = Arc::new(SharedCache::default());
        owner.require_copy_containment_for_test();
        let mut state = CopyObservationState::default();
        let result = state.replace(
            &owner,
            index.copy_containment_status(Some(100)),
            "durable_selected_index",
            1,
        );
        if !super::super::required_decode::profile_supported() {
            assert_eq!(result, None);
            assert_eq!(serde_json::to_vec(&index).unwrap(), debt_before);
            writeln!(std::io::stderr().lock(), "copy_containment_typed_status_pressure: unsupported_before_slot=true required_debt_unchanged=true positive_pressure_projection_and_recovery=UNEXECUTED").unwrap();
            return;
        }
        assert_eq!(result, Some(true));
        let persistent = owner.reserved_copy_bytes_for_test().unwrap();
        // Byte credits, not fake allocated native state or a new capacity cap.
        let mut other_owners = Vec::new();
        while let Some(credit) = owner.reserve_copy_bytes(1024) {
            other_owners.push(credit);
        }
        let (_, refused) = crate::retry_allocation_probe::measure(|| {
            assert!(state.prepay_projection("otm_synthetic", 0).is_none());
        });
        assert_eq!(refused.allocations, 0);
        assert_eq!(state.last_sequence(), 1);
        assert_eq!(serde_json::to_vec(&index).unwrap(), debt_before);
        assert_eq!(index.copy_hold_count(), 1);
        drop(other_owners);
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(persistent));
        let (_, actual) = crate::retry_allocation_probe::measure(|| {
            let projection = state.prepay_projection("otm_synthetic", 0).unwrap();
            let paid = projection._credit.bytes();
            let mut events = Vec::new();
            let output = projection.append(&mut events).unwrap();
            assert_eq!(events[0].payload["observation"]["held_revision_count"], 1);
            assert!(crate::retry_allocation_probe::stats().requested_peak_with_overlap <= paid);
            drop(events);
            drop(output);
        });
        assert_eq!(actual.requested_live, 0);
        assert_eq!(serde_json::to_vec(&index).unwrap(), debt_before);
        drop(state);
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(0));
        writeln!(std::io::stderr().lock(), "copy_containment_typed_status_pressure: positive_projection_executed=true allocation_refusal_before_output=true required_debt_bytes_unchanged=true private_record_kept=true credits_recovered=true final_slot_drop_returns_credit=true").unwrap();
    }
}
