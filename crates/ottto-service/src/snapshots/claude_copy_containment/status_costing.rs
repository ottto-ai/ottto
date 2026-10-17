//! Non-retaining shape costs for the closed content-free observation only.
//! Source-only: not a status admission gate or an aggregate daemon/RSS bound.
use super::required_budget::LIMIT;
use crate::heap_layout_bound::{self, Counter};
use serde::ser::{Impossible, SerializeStruct};
use serde::{Serialize, Serializer};
use std::fmt;
use std::mem::size_of;

#[derive(Debug, Clone, Copy)]
struct Unknown;
impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown closed observation shape")
    }
}
impl std::error::Error for Unknown {}
impl serde::ser::Error for Unknown {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}

#[derive(Debug, Clone, Copy)]
struct Shape {
    heap: usize,
    wire_upper: usize,
}
impl Shape {
    fn scalar(wire_upper: usize) -> Self {
        Self {
            heap: 0,
            wire_upper,
        }
    }
    fn checked(heap: usize, wire_upper: usize) -> Result<Self, Unknown> {
        if heap > LIMIT || wire_upper > LIMIT {
            return Err(Unknown);
        }
        Ok(Self { heap, wire_upper })
    }
}
fn escaped(value: &str) -> Result<usize, Unknown> {
    // Canonical JSON escapes at most six bytes per input UTF8 byte. This is
    // representation length only: do not materialize an escaped temporary.
    value
        .len()
        .checked_mul(6)
        .and_then(|n| n.checked_add(2))
        .ok_or(Unknown)
}
struct Sizer;
struct StructSizer {
    expected: usize,
    seen: usize,
    shape: Shape,
}
macro_rules! signed { ($($name:ident:$t:ty),*) => {$ (
    fn $name(self, _: $t) -> Result<Shape, Unknown> { Ok(Shape::scalar(21)) }
)*}; }
macro_rules! unsigned { ($($name:ident:$t:ty),*) => {$ (
    fn $name(self, _: $t) -> Result<Shape, Unknown> { Ok(Shape::scalar(20)) }
)*}; }
impl Serializer for Sizer {
    type Ok = Shape;
    type Error = Unknown;
    type SerializeSeq = Impossible<Shape, Unknown>;
    type SerializeTuple = Impossible<Shape, Unknown>;
    type SerializeTupleStruct = Impossible<Shape, Unknown>;
    type SerializeTupleVariant = Impossible<Shape, Unknown>;
    type SerializeMap = Impossible<Shape, Unknown>;
    type SerializeStruct = StructSizer;
    type SerializeStructVariant = Impossible<Shape, Unknown>;
    signed!(serialize_i8:i8, serialize_i16:i16, serialize_i32:i32, serialize_i64:i64);
    unsigned!(serialize_u8:u8, serialize_u16:u16, serialize_u32:u32, serialize_u64:u64);
    fn serialize_bool(self, _: bool) -> Result<Shape, Unknown> {
        Ok(Shape::scalar(5))
    }
    fn serialize_str(self, value: &str) -> Result<Shape, Unknown> {
        Shape::checked(value.len(), escaped(value)?)
    }
    fn serialize_none(self) -> Result<Shape, Unknown> {
        // The closed observation uses optional bool/u64/usize only. Bound a
        // concurrent later Some without retaining its value or walking again.
        Ok(Shape::scalar(20))
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Shape, Unknown> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Shape, Unknown> {
        Ok(Shape::scalar(4))
    }
    fn serialize_i128(self, _: i128) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_u128(self, _: u128) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_f32(self, _: f32) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_f64(self, _: f64) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_char(self, _: char) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Shape, Unknown> {
        Err(Unknown)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Unknown> {
        Err(Unknown)
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Unknown> {
        Err(Unknown)
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Unknown> {
        Err(Unknown)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Unknown> {
        Err(Unknown)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Unknown> {
        Err(Unknown)
    }
    fn serialize_struct(self, _: &'static str, len: usize) -> Result<StructSizer, Unknown> {
        let mut nodes = Counter::new(LIMIT);
        heap_layout_bound::tree_nodes::<String, serde_json::Value>(len, &mut nodes)
            .ok_or(Unknown)?;
        let wire_upper = len.saturating_sub(1).checked_add(2).ok_or(Unknown)?;
        Ok(StructSizer {
            expected: len,
            seen: 0,
            shape: Shape::checked(nodes.bytes, wire_upper)?,
        })
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Unknown> {
        Err(Unknown)
    }
    fn collect_str<T: ?Sized + fmt::Display>(self, _: &T) -> Result<Shape, Unknown> {
        // The default collect_str formats an owned String before cost is
        // known. Never invoke it for an unknown/custom representation.
        Err(Unknown)
    }
}
impl SerializeStruct for StructSizer {
    type Ok = Shape;
    type Error = Unknown;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Unknown> {
        self.seen = self.seen.checked_add(1).ok_or(Unknown)?;
        if self.seen > self.expected {
            return Err(Unknown);
        }
        let child = value.serialize(Sizer)?;
        self.shape = Shape::checked(
            self.shape
                .heap
                .checked_add(key.len())
                .and_then(|n| n.checked_add(child.heap))
                .ok_or(Unknown)?,
            self.shape
                .wire_upper
                .checked_add(escaped(key)?)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| n.checked_add(child.wire_upper))
                .ok_or(Unknown)?,
        )?;
        Ok(())
    }
    fn end(self) -> Result<Shape, Unknown> {
        if self.seen != self.expected {
            return Err(Unknown);
        }
        Ok(self.shape)
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::snapshots) struct StatusCosts {
    pub(in crate::snapshots) payload_heap: usize,
    pub(in crate::snapshots) payload_wire_upper: usize,
    pub(in crate::snapshots) two_projection_payloads: usize,
    pub(in crate::snapshots) full_event_vec_replace_peak: usize,
}
/// Byte-only observation; no field value/ID/history is captured. This model
/// covers a single known internal operation. A persistent owner/lease and
/// explicit API ownership-transfer boundary are still required before wiring.
pub(in crate::snapshots) fn closed_status_costs<T: Serialize>(
    observation: &T,
    event_len: usize,
    event_capacity: usize,
) -> Option<StatusCosts> {
    if !super::required_decode::profile_supported() {
        return None;
    }
    let shape = observation.serialize(Sizer).ok()?;
    if event_capacity < event_len {
        return None;
    }
    let next = event_len.checked_add(1)?;
    let new_capacity = if next <= event_capacity {
        event_capacity
    } else {
        event_capacity.checked_mul(2)?.max(next).max(4)
    };
    // Full old+new slot buffer when this operation crosses the threshold.
    // Payload referents in unrelated slots remain their existing owners.
    let slots = if next <= event_capacity {
        0
    } else {
        event_capacity.checked_add(new_capacity)?
    };
    let full_event_vec_replace_peak =
        slots.checked_mul(size_of::<ottto_protocol::LocalHealthEventV1>())?;
    let two_projection_payloads = shape.heap.checked_mul(2)?;
    Some(StatusCosts {
        payload_heap: shape.heap,
        payload_wire_upper: shape.wire_upper,
        two_projection_payloads,
        full_event_vec_replace_peak,
    })
}
/// Complete output-buffer representation bound, including unchanged baseline.
/// Reporting this value does NOT make the entire caller-owned response a new
/// shared-cache owner or impose a totaldaemon/RSS limit.
pub(in crate::snapshots) fn serialization_representation(bytes: usize) -> Option<(usize, usize)> {
    let rust_vec_growth_peak = bytes.max(128).checked_mul(4)?;
    let xpc_string_cstring_strdup_peak = bytes.checked_add(1)?.max(128).checked_mul(6)?;
    Some((rust_vec_growth_peak, xpc_string_cstring_strdup_peak))
}

/// A new observation can cross a decimal sequence boundary. Pay the full
/// affected runtime id String owners, not only the one added digit: format,
/// event clone and evidence clone (plus the returned event's owned Value).
pub(in crate::snapshots) fn runtime_sequence_string_peak(copies: usize) -> Option<usize> {
    "evt_runtime_observed_"
        .len()
        .checked_add(20)?
        .checked_mul(2)?
        .checked_mul(copies)
}

/// Full slot-buffer overlap through the initial append and the existing
/// canonical projection's clone-then-push. Includes unchanged baseline slots
/// conservatively when the extra observation crosses a growth threshold;
/// unrelated payload referents remain baseline owners.
pub(in crate::snapshots) fn projection_slot_peak(existing: usize) -> Option<usize> {
    let first_len = existing.checked_add(1)?;
    let first_capacity = existing.checked_mul(2)?.max(first_len).max(4);
    let final_len = first_len.checked_add(1)?;
    let final_capacity = first_len.checked_mul(2)?.max(final_len).max(4);
    let initial = existing.checked_add(first_capacity)?;
    let projection = first_capacity
        .checked_add(first_len)?
        .checked_add(final_capacity)?;
    initial
        .max(projection)
        .checked_mul(size_of::<ottto_protocol::LocalHealthEventV1>())
}

/// Inspect only the already materialized closed local observation. Borrowed
/// scalars/strings, no serialization, ID retention or new collection. Refuse
/// structural additions until their new ownership has been qualified.
fn existing_payload_shape(value: &serde_json::Value) -> Option<Shape> {
    let root = value.as_object()?;
    if root.len() != 5
        || !["kind", "current", "basis", "observation", "message"]
            .iter()
            .all(|key| root.contains_key(*key))
    {
        return None;
    }
    let observation = root.get("observation")?.as_object()?;
    if observation.len() != 18 || observation.get("reasons")?.as_object()?.len() != 4 {
        return None;
    }
    fn visit(value: &serde_json::Value, depth: usize) -> Option<Shape> {
        match value {
            serde_json::Value::Null => Some(Shape::scalar(4)),
            serde_json::Value::Bool(_) => Some(Shape::scalar(5)),
            serde_json::Value::Number(number) if number.is_u64() => Some(Shape::scalar(20)),
            serde_json::Value::String(value) => {
                Shape::checked(value.capacity(), escaped(value).ok()?).ok()
            }
            serde_json::Value::Object(map) if depth < 3 => {
                let mut nodes = Counter::new(LIMIT);
                heap_layout_bound::tree_nodes::<String, serde_json::Value>(map.len(), &mut nodes)?;
                let mut shape =
                    Shape::checked(nodes.bytes, map.len().saturating_sub(1).checked_add(2)?)
                        .ok()?;
                for (key, value) in map {
                    let child = visit(value, depth + 1)?;
                    shape = Shape::checked(
                        shape
                            .heap
                            .checked_add(key.capacity())?
                            .checked_add(child.heap)?,
                        shape
                            .wire_upper
                            .checked_add(escaped(key).ok()?)?
                            .checked_add(1)?
                            .checked_add(child.wire_upper)?,
                    )
                    .ok()?;
                }
                Some(shape)
            }
            _ => None,
        }
    }
    visit(value, 0)
}

/// Status-only second canonical projection + owned Value conversion. This is
/// before response transfer, not a credit carried into transport or C ABI.
pub(in crate::snapshots) fn control_status_peak(
    status: &ottto_protocol::DaemonStatus,
) -> Option<usize> {
    if !super::required_decode::profile_supported() {
        return None;
    }
    let event = status
        .local_health_events
        .iter()
        .find(|event| event.event_type == crate::snapshot_sync::COPY_CONTAINMENT_EVENT_TYPE)?;
    if event.source_id.is_some() || event.action_id.is_some() {
        return None;
    }
    let payload = existing_payload_shape(&event.payload)?;
    let strings = [
        &event.event_id,
        &event.event_schema_version,
        &event.event_type,
        &event.machine_id,
        &event.observed_at,
    ]
    .iter()
    .try_fold(0usize, |sum, value| sum.checked_add(value.capacity()))?;
    let event_heap = strings.checked_add(payload.heap)?;
    // Serialized LocalHealthEvent has eight fields; source/action are absent.
    let mut nodes = Counter::new(LIMIT);
    heap_layout_bound::tree_nodes::<String, serde_json::Value>(8, &mut nodes)?;
    let keys = [
        "event_id",
        "event_schema_version",
        "event_type",
        "machine_id",
        "observed_at",
        "sequence",
        "authority",
        "payload",
    ]
    .iter()
    .try_fold(0usize, |sum, key| sum.checked_add(key.len()))?;
    let value_heap = nodes
        .bytes
        .checked_add(keys)?
        .checked_add(event_heap)?
        .checked_add("runtime".len())?;
    let n = status.local_health_events.len();
    let next_capacity = n.checked_mul(2)?.max(n.checked_add(1)?).max(4);
    let vector_peak = status
        .local_health_events
        .capacity()
        .checked_add(n)?
        .checked_add(next_capacity)?
        .checked_mul(size_of::<ottto_protocol::LocalHealthEventV1>())?;
    // serde_json1.0.149 SerializeSeq reserves exactly its supplied length.
    let value_slots = n
        .checked_add(1)?
        .checked_mul(size_of::<serde_json::Value>())?;
    let bytes = event_heap
        .checked_mul(2)?
        .checked_add(runtime_sequence_string_peak(6)?)?
        .checked_add(value_heap)?
        .checked_add(vector_peak)?
        .checked_add(value_slots)?;
    (bytes <= LIMIT).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use crate::snapshots::ScanIndex;

    use super::*;
    use ottto_protocol::{LocalHealthAuthority, LocalHealthEventV1};
    use std::io::Write as _;

    #[test]
    fn copy_containment_status_vec_growth_bound_matches_actual_clone_append_projection_lifetimes() {
        fn empty_event() -> LocalHealthEventV1 {
            LocalHealthEventV1 {
                event_id: String::new(),
                event_schema_version: String::new(),
                event_type: String::new(),
                machine_id: String::new(),
                observed_at: String::new(),
                sequence: 0,
                authority: LocalHealthAuthority::Runtime,
                source_id: None,
                action_id: None,
                payload: serde_json::Value::Null,
            }
        }
        for n in [0usize, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64] {
            // No payload referents; the probe isolates actual full slot-buffer
            // peaks at each clone/append boundary, independent of the formula.
            let baseline = (0..n).map(|_| empty_event()).collect::<Vec<_>>();
            let (_, actual) = crate::retry_allocation_probe::measure(|| {
                let mut first = baseline.clone();
                assert_eq!(first.capacity(), n, "pinned Vec clone shape");
                first.insert(n / 2, empty_event());
                let mut projected = first.clone();
                projected.push(empty_event());
                assert_eq!(projected.len(), n + 2);
                drop(first);
                drop(projected);
            });
            let bound = projection_slot_peak(n).unwrap();
            assert!(
                actual.requested_peak_with_overlap <= bound,
                "n={n}: {actual:?}, bound={bound}"
            );
            assert_eq!(actual.requested_live, 0);
            writeln!(std::io::stderr().lock(), "copy_containment_status_vec_peak: n={n} actual_requested={} conservative_full_slot_peak={bound} baseline_payloads_excluded=true", actual.requested_peak_with_overlap).unwrap();
        }
        assert!(projection_slot_peak(usize::MAX).is_none());
    }
    use super::*;
    use crate::snapshots::ScanIndex;
    #[test]
    fn copy_containment_control_observation_shape_is_borrowed_and_refuses_structural_drift() {
        let value = serde_json::json!({"kind":"claude_copy_containment", "current":true,
            "basis":"durable_selected_index", "message":"content-free synthetic observation",
            "observation":ScanIndex::default().copy_containment_status(Some(100))});
        let (shape, actual) =
            crate::retry_allocation_probe::measure(|| existing_payload_shape(&value).unwrap());
        assert_eq!(actual.allocations, 0);
        assert!(shape.wire_upper >= serde_json::to_vec(&value).unwrap().len());
        let mut changed = value.clone();
        changed["observation"]["new_field"] = serde_json::json!(0);
        assert!(existing_payload_shape(&changed).is_none());
        changed = value;
        changed["observation"]["reasons"] = serde_json::json!([]);
        assert!(existing_payload_shape(&changed).is_none());
    }
}
