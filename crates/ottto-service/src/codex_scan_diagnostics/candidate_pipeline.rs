//! Optional observations only: no admission, cursor, retry or accounting authority.
use super::{census_attempt, digest, process_start};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    #[default]
    Identified,
    Selected,
    Parsed,
    Finalized,
    Queued,
    ValidatedDelivery,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Hold {
    #[default]
    None,
    Skip,
    Migrate,
    ReconcileLegacy,
    HeaderInventory,
    ParentPending,
    Ownership,
    LineLoss,
    MultiEntity,
    NotInQueue,
    LocalState,
    DeliveryDeferred,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Delivery {
    #[default]
    Unobserved,
    Accepted,
    Unchanged,
    Rejected,
    Conflict,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct Binding {
    pid: u32,
    start_sec: Option<u64>,
    start_usec: Option<u64>,
    attempt: Option<u64>,
}
pub(crate) fn binding() -> Binding {
    let start = process_start();
    Binding {
        pid: std::process::id(),
        start_sec: start.map(|s| s.sec),
        start_usec: start.map(|s| s.usec),
        attempt: census_attempt(),
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Sample {
    file_key_digest: [u8; 32],
    #[serde(skip)]
    rank: [u8; 32],
    entity_digest: Option<[u8; 32]>,
    finalized_group_body_digest: Option<[u8; 32]>,
    validated_request_body_digest: Option<[u8; 32]>,
    previous_checkpoint_present: Option<bool>,
    metadata_changed: Option<bool>,
    file_fingerprint_changed: Option<bool>,
    group_body_changed: Option<bool>,
    pub stage: Stage,
    pub first_hold: Hold,
    pub delivery: Delivery,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct CandidatePipeline {
    pub binding: Binding,
    pub generation: u64,
    pub terminal: bool,
    // Counts of observations, not distinct sessions or billing requests.
    pub decisions: u64,
    pub parsed: u64,
    pub finalized: u64,
    pub overflowed: bool,
    // Coverage is ONLY these two identified objects; no discovery/absence claim.
    pub samples: [Option<Sample>; 2],
}
impl CandidatePipeline {
    pub fn identify(&mut self, key: &str, generation: u64) {
        #[cfg(test)]
        if TEST_IDENTIFY_DISABLED.with(std::cell::Cell::get) {
            return;
        }
        self.generation = generation;
        let key = digest(key);
        if self
            .samples
            .iter()
            .flatten()
            .any(|s| s.file_key_digest == key)
        {
            return;
        }
        let mut material = [0u8; 40];
        material[..32].copy_from_slice(&key);
        material[32..].copy_from_slice(&generation.to_le_bytes());
        use sha2::{Digest, Sha256};
        let rank: [u8; 32] = Sha256::digest(material).into();
        let sample = Sample {
            file_key_digest: key,
            rank,
            entity_digest: None,
            finalized_group_body_digest: None,
            validated_request_body_digest: None,
            previous_checkpoint_present: None,
            metadata_changed: None,
            file_fingerprint_changed: None,
            group_body_changed: None,
            stage: Stage::Identified,
            first_hold: Hold::None,
            delivery: Delivery::Unobserved,
        };
        if let Some(slot) = self.samples.iter_mut().find(|s| s.is_none()) {
            *slot = Some(sample);
            return;
        }
        let slot = if self.samples[0].unwrap().rank > self.samples[1].unwrap().rank {
            0
        } else {
            1
        };
        if rank < self.samples[slot].unwrap().rank {
            self.samples[slot] = Some(sample);
        }
    }
    fn count(value: &mut u64, overflowed: &mut bool) {
        if let Some(v) = value.checked_add(1) {
            *value = v;
        } else {
            *overflowed = true;
        }
    }
    fn sample(&mut self, key: &str) -> Option<&mut Sample> {
        let key = digest(key);
        self.samples
            .iter_mut()
            .flatten()
            .find(|s| s.file_key_digest == key)
    }
    fn hold(sample: &mut Sample, hold: Hold) {
        if sample.first_hold == Hold::None {
            sample.first_hold = hold;
        }
    }
    pub fn context(
        &mut self,
        key: &str,
        previous: bool,
        metadata: Option<bool>,
        fingerprint: Option<bool>,
    ) {
        if let Some(s) = self.sample(key) {
            s.previous_checkpoint_present = Some(previous);
            s.metadata_changed = metadata;
            s.file_fingerprint_changed = fingerprint;
        }
    }
    pub fn group_body_change(&mut self, key: &str, changed: Option<bool>) {
        if let Some(s) = self.sample(key) {
            s.group_body_changed = changed;
        }
    }
    pub fn deferred(&mut self) {
        for s in self.samples.iter_mut().flatten() {
            if s.stage == Stage::Queued {
                Self::hold(s, Hold::DeliveryDeferred);
            }
        }
    }
    pub fn decision(&mut self, key: &str, hold: Hold) {
        Self::count(&mut self.decisions, &mut self.overflowed);
        if let Some(s) = self.sample(key) {
            s.stage = Stage::Selected;
            Self::hold(s, hold);
        }
    }
    pub fn parsed(&mut self, key: &str, hold: Hold) {
        Self::count(&mut self.parsed, &mut self.overflowed);
        if let Some(s) = self.sample(key) {
            s.stage = Stage::Parsed;
            Self::hold(s, hold);
        }
    }
    pub fn header_incomplete(&mut self) {
        for s in self.samples.iter_mut().flatten() {
            Self::hold(s, Hold::HeaderInventory);
        }
    }
    pub fn finalized(
        &mut self,
        key: &str,
        entities: &std::collections::BTreeSet<String>,
        group_body: Option<&str>,
    ) {
        Self::count(&mut self.finalized, &mut self.overflowed);
        if let Some(s) = self.sample(key) {
            s.stage = Stage::Finalized;
            s.entity_digest = None;
            s.validated_request_body_digest = None;
            s.delivery = Delivery::Unobserved;
            s.finalized_group_body_digest = group_body.map(digest);
            if entities.len() == 1 {
                s.entity_digest = entities.first().map(|e| digest(e));
            } else {
                Self::hold(s, Hold::MultiEntity);
            }
        }
    }
    pub fn queue<'a>(&mut self, entities: impl Iterator<Item = &'a str>) {
        // Inspect at most two samples against the already finalized queue; no extra source IO.
        let mut found = [false; 2];
        for entity in entities {
            let entity = digest(entity);
            for (i, s) in self.samples.iter_mut().enumerate() {
                if let Some(s) = s {
                    if s.entity_digest == Some(entity) {
                        s.stage = Stage::Queued;
                        found[i] = true;
                    }
                }
            }
        }
        for (i, s) in self.samples.iter_mut().enumerate() {
            if let Some(s) = s {
                if s.stage == Stage::Finalized && !found[i] {
                    Self::hold(s, Hold::NotInQueue);
                }
            }
        }
    }
    pub fn tracks(&self, entity: &str) -> bool {
        let key = digest(entity);
        self.samples
            .iter()
            .flatten()
            .any(|s| s.entity_digest == Some(key))
    }
    // Caller must first validate exact request entities, body witness and ACK contract.
    pub fn validated(&mut self, entity: &str, body: &str, delivery: Delivery) {
        let key = digest(entity);
        for s in self.samples.iter_mut().flatten() {
            if s.entity_digest == Some(key) {
                s.stage = Stage::ValidatedDelivery;
                s.delivery = delivery;
                s.validated_request_body_digest = Some(digest(body));
            }
        }
    }
    pub fn local_state_failed(&mut self) {
        for s in self.samples.iter_mut().flatten() {
            if s.stage == Stage::ValidatedDelivery {
                Self::hold(s, Hold::LocalState);
            }
        }
    }
}
crate::heap_layout_bound::fields!(CandidatePipeline; binding,generation,terminal,decisions,parsed,finalized,overflowed,samples);
crate::heap_layout_bound::fields!(Binding; pid,start_sec,start_usec,attempt);
crate::heap_layout_bound::fields!(Sample; file_key_digest,rank,entity_digest,finalized_group_body_digest,validated_request_body_digest,previous_checkpoint_present,metadata_changed,file_fingerprint_changed,group_body_changed,stage,first_hold,delivery);
macro_rules! bounded_enum {
    ($t:ty) => {
        impl crate::heap_layout_bound::HeapLayoutBound for $t {
            fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
                c.add(0)
            }
        }
    };
}
bounded_enum!(Stage);
bounded_enum!(Hold);
bounded_enum!(Delivery);
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_pipeline_first_hold_and_independent_trace() {
        let mut p = CandidatePipeline::default();
        p.identify("private-path", 7);
        p.decision("private-path", Hold::None);
        p.parsed("private-path", Hold::Ownership);
        p.finalized(
            "private-path",
            &std::collections::BTreeSet::from(["entity".into()]),
            Some("group-body"),
        );
        p.queue(std::iter::once("entity"));
        p.validated("entity", "request-body", Delivery::Accepted);
        p.local_state_failed();
        let s = p.samples.iter().flatten().next().unwrap();
        assert_eq!(s.first_hold, Hold::Ownership);
        assert_eq!(s.delivery, Delivery::Accepted);
        assert_eq!((p.decisions, p.parsed, p.finalized), (1, 1, 1));
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("private-path"));
        assert!(!json.contains("\"entity\""));
    }
    #[test]
    fn candidate_pipeline_never_offered_and_unsampled_stay_unknown() {
        let mut p = CandidatePipeline::default();
        p.identify("one", 1);
        p.decision("one", Hold::Skip);
        assert_eq!(p.samples[0].unwrap().delivery, Delivery::Unobserved);
        p.validated("unmatched", "request-body", Delivery::Accepted);
        assert_eq!(p.samples[0].unwrap().delivery, Delivery::Unobserved);
        assert!(std::mem::size_of::<CandidatePipeline>() <= 768);
    }
    #[test]
    fn candidate_pipeline_overflow_and_multientity_do_not_certify() {
        let mut p = CandidatePipeline::default();
        p.identify("one", 1);
        p.decisions = u64::MAX;
        p.decision("one", Hold::None);
        assert!(p.overflowed);
        p.finalized(
            "one",
            &std::collections::BTreeSet::from(["a".into(), "b".into()]),
            Some("group-body"),
        );
        p.queue(["a", "b"].into_iter());
        assert_eq!(p.samples[0].unwrap().first_hold, Hold::MultiEntity);
        assert_eq!(p.samples[0].unwrap().delivery, Delivery::Unobserved);
    }
}

#[cfg(test)]
thread_local! {static TEST_IDENTIFY_DISABLED:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}
#[cfg(test)]
pub(crate) fn without_samples<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_IDENTIFY_DISABLED.with(|v| v.set(self.0));
        }
    }
    let _guard = Restore(TEST_IDENTIFY_DISABLED.with(|v| v.replace(true)));
    f()
}
