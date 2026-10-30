//! Counts of the selected stale-start carry route, captured before clearing.
//! Fixed stack storage only; never source identifiers, proof or persisted state.
use serde::Serialize;

#[derive(Clone, Copy)]
pub(super) enum Rejection {
    ProvenanceOrContext,
    Contract,
    AcceptedLedger,
    UploadContext,
    WindowScratch,
    OrdinaryScratch,
    MemberEvidence,
    CancellationFunding,
    ReserveAllocation,
}
impl From<super::ClaudeRetryAdmissionRefusal> for Rejection {
    fn from(value: super::ClaudeRetryAdmissionRefusal) -> Self {
        match value {
            super::ClaudeRetryAdmissionRefusal::Structure => Self::OrdinaryScratch,
            super::ClaudeRetryAdmissionRefusal::Funding => Self::CancellationFunding,
            super::ClaudeRetryAdmissionRefusal::Allocation => Self::ReserveAllocation,
        }
    }
}
/// Overlapping observations, separate from the conserved rejection totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct UnknownCounts {
    unknown_missing_witness: u64,
    unknown_incomplete_member: u64,
    unknown_compacted_origin: u64,
    unknown_decode: u64,
    unknown_resource: u64,
    unknown_dependency: u64,
    unknown_global: u64,
}
impl UnknownCounts {
    #[cfg(test)]
    fn maximum() -> Self {
        Self {
            unknown_missing_witness: u64::MAX,
            unknown_incomplete_member: u64::MAX,
            unknown_compacted_origin: u64::MAX,
            unknown_decode: u64::MAX,
            unknown_resource: u64::MAX,
            unknown_dependency: u64::MAX,
            unknown_global: u64::MAX,
        }
    }
}
macro_rules! counts {
    ($($field:ident: $stage:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
        pub(super) struct Counts {
            $(pub(super) $field: u64,)+
            pub(super) eligible_before_funding: u64,
            pub(super) final_carried: u64,
            #[serde(flatten)]
            pub(super) unknown: UnknownCounts,
        }
        impl Counts {
            pub(super) fn reject(&mut self, stage: Rejection, roots: usize) {
                let count = match stage { $(Rejection::$stage => &mut self.$field,)+ };
                *count = count.saturating_add(roots as u64);
            }
            pub(super) fn rejected(&self) -> u64 {
                0_u64$(.saturating_add(self.$field))+
            }
            #[cfg(test)]
            fn maximum() -> Self {
                Self { $($field: u64::MAX,)+ eligible_before_funding: u64::MAX, final_carried: u64::MAX, unknown: UnknownCounts::maximum() }
            }
        }
    };
}
counts! {
    provenance_or_context: ProvenanceOrContext,
    contract: Contract,
    accepted_ledger: AcceptedLedger,
    upload_context: UploadContext,
    window_scratch: WindowScratch,
    ordinary_scratch: OrdinaryScratch,
    member_evidence: MemberEvidence,
    cancellation_funding: CancellationFunding,
    reserve_allocation: ReserveAllocation,
}
impl Counts {
    pub(super) fn observe_unknown(
        &mut self,
        index: &super::ScanIndex,
        roots: &std::collections::BTreeSet<String>,
    ) {
        use super::usage_pending_guard::Unknown;
        self.unknown = UnknownCounts::default();
        if index.usage_guard_holds.global() {
            self.unknown.unknown_global = 1;
            return;
        }
        for root in roots {
            let counter = match index.usage_guard_reason(root) {
                Some(Unknown::MissingWitness) => &mut self.unknown.unknown_missing_witness,
                Some(Unknown::IncompleteMember) => &mut self.unknown.unknown_incomplete_member,
                Some(Unknown::CompactedOrigin) => &mut self.unknown.unknown_compacted_origin,
                Some(Unknown::Decode) => &mut self.unknown.unknown_decode,
                Some(Unknown::Resource) => &mut self.unknown.unknown_resource,
                Some(Unknown::Dependency) => &mut self.unknown.unknown_dependency,
                None => continue,
            };
            *counter = counter.saturating_add(1);
        }
    }
    pub(super) fn has_unknown(&self) -> bool {
        self.unknown != UnknownCounts::default()
    }
    pub(super) fn start_gate(index: &super::ScanIndex, same_context: bool) -> Rejection {
        if !same_context {
            Rejection::ProvenanceOrContext
        } else if index.claude_request_identity_contract_changed
            || index.claude_request_identity_contract.is_none()
        {
            Rejection::Contract
        } else if !super::claude_accepted_ledger_is_current(index) {
            Rejection::AcceptedLedger
        } else if index.upload_context_fingerprint != index.active_upload_context_fingerprint {
            Rejection::UploadContext
        } else {
            // Legacy fence/independent-acceptance admission did not qualify.
            Rejection::MemberEvidence
        }
    }
    /// Serialization runs only where the pre-existing re-arm line is emitted.
    pub(super) fn json(&self) -> String {
        serde_json::to_string(self).expect("fixed integer counters serialize")
    }
    pub(super) fn record_before_clear(&self, _stale_roots: usize) {
        #[cfg(test)]
        {
            assert_eq!(
                self.rejected().saturating_add(self.final_carried),
                _stale_roots as u64,
                "each stale root has exactly one rejection or final carry"
            );
            LAST.with(|last| last.set(Some(*self)));
        }
    }
}
#[cfg(test)]
thread_local! {
    static LAST: std::cell::Cell<Option<Counts>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(super) fn take_for_test() -> Option<Counts> {
    LAST.with(|last| last.take())
}
/// Identical production reservation; the test seam triggers a real capacity
/// overflow error without exhausting memory or changing any admission budget.
pub(super) fn reserve<T>(
    values: &mut Vec<T>,
    slots: usize,
) -> Result<(), std::collections::TryReserveError> {
    #[cfg(test)]
    if REFUSE_RESERVE.with(std::cell::Cell::get) {
        return values.try_reserve_exact(usize::MAX);
    }
    values.try_reserve_exact(slots)
}
#[cfg(test)]
thread_local! {
    static REFUSE_RESERVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(super) fn refusing_reserve<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSE_RESERVE.with(|cell| cell.set(self.0));
        }
    }
    let _reset = Reset(REFUSE_RESERVE.with(|cell| cell.replace(true)));
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_schema_is_bounded_and_saturates() {
        let mut counts = Counts::maximum();
        counts.reject(Rejection::ReserveAllocation, 1);
        assert_eq!(counts.reserve_allocation, u64::MAX);
        let encoded = counts.json();
        assert!(encoded.len() < 1280);
        assert!(std::mem::size_of::<Counts>() <= 144);
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 18);
        assert!(value
            .as_object()
            .unwrap()
            .values()
            .all(|n| n.as_u64() == Some(u64::MAX)));
    }
}
