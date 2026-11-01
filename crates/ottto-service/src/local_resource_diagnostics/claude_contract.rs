//! Counts on the existing page/decision carrier; never authority or wire data.
use super::claude_reread;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
#[cfg(not(test))]
use std::sync::Mutex;

macro_rules! counters {
    ($name:ident { $($field:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
        pub(crate) struct $name { $(#[serde(skip_serializing_if = "super::is_zero")] pub(crate) $field: u64),+ }
        impl $name {
            fn is_empty(&self) -> bool { *self == Self::default() }
            fn merge(&mut self, other: Self) { $(self.$field = self.$field.saturating_add(other.$field);)+ }
        }
    };
}
counters!(Transition {
    from_empty,
    to_empty,
    collector_e2_grouping,
    mid_traversal_placeholder
});
counters!(Latch {
    set,
    cleared,
    cleared_with_quarantine_exempt,
    quarantine_exempt_families
});
// Lead A ruling (a): the one cutover terminal (`runs`) and the files and bytes it re-armed.
counters!(CutoverRearm { runs, files, bytes });
counters!(ContextChange {
    backfill_changed,
    active_upload_context_changed,
    policy_changed,
    attribution_available_changed,
    attribution_epoch_changed,
    cache_capability_changed,
    replay_changed,
    roots_changed
});
// Evidence owed ON: each owed member the traversal's selection
// visits, by outcome, by why a re-stamp was refused, and by the age of its
// family's stored evidence window against this census window.
counters!(EvidenceOwed {
    restamped,
    restamped_from_record,
    restamped_under_latch,
    read,
    selected_by_other_reason,
    deferred_page_cap,
    owed_waiting_cap,
    changed,
    refused_contract_latch,
    refused_contract_unproven,
    refused_scan_identity,
    refused_pending_invalid,
    refused_evidence,
    refused_record,
    refused_family_unverified,
    refused_no_pending,
    age_le_1h,
    age_le_1d,
    age_le_7d,
    age_gt_7d,
    age_unknown,
    identity_contract_owed,
    identity_owed_read_under_latch,
    queue_at_page_start_under_latch
});
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Counts {
    #[serde(skip_serializing_if = "Transition::is_empty")]
    pub(crate) identity_contract_transition: Transition,
    #[serde(skip_serializing_if = "Latch::is_empty")]
    pub(crate) identity_contract_latch: Latch,
    #[serde(skip_serializing_if = "CutoverRearm::is_empty")]
    pub(crate) contract_cutover_rearm: CutoverRearm,
    #[serde(skip_serializing_if = "ContextChange::is_empty")]
    pub(crate) traversal_context_change: ContextChange,
    #[serde(skip_serializing_if = "super::is_zero")]
    pub(crate) deferred_by_contract_debt: u64,
    #[serde(skip_serializing_if = "EvidenceOwed::is_empty")]
    pub(crate) evidence_owed: EvidenceOwed,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) root_count: Option<u64>,
}
impl Counts {
    pub(crate) fn merge(&mut self, other: Self) {
        self.identity_contract_transition
            .merge(other.identity_contract_transition);
        self.identity_contract_latch
            .merge(other.identity_contract_latch);
        self.contract_cutover_rearm
            .merge(other.contract_cutover_rearm);
        self.traversal_context_change
            .merge(other.traversal_context_change);
        self.deferred_by_contract_debt = self
            .deferred_by_contract_debt
            .saturating_add(other.deferred_by_contract_debt);
        self.evidence_owed.merge(other.evidence_owed);
        self.root_count = other.root_count.or(self.root_count);
    }
}
pub(crate) fn note(f: impl FnOnce(&mut Counts)) {
    claude_reread::update(|counts| f(&mut counts.contract));
}
fn roots_digest(roots: &[PathBuf]) -> [u8; 32] {
    let mut hash = Sha256::new_with_prefix(b"ottto:traversal-roots:v1\0");
    for root in roots {
        let root: PathBuf = root.components().collect();
        hash.update((root.as_os_str().len() as u64).to_be_bytes());
        hash.update(root.as_os_str().as_encoded_bytes());
    }
    hash.finalize().into()
}
type Parts = [Option<[u8; 32]>; 7];
#[derive(Default)]
struct ContextState {
    prepared: [Option<[u8; 32]>; 3],
    retained: Option<(String, Parts, [u8; 32])>,
}
#[cfg(not(test))]
static CONTEXT: Mutex<ContextState> = Mutex::new(ContextState {
    prepared: [None; 3],
    retained: None,
});
#[cfg(test)]
thread_local! { static CONTEXT: std::cell::RefCell<ContextState> = Default::default(); }
fn context<T>(f: impl FnOnce(&mut ContextState) -> T) -> T {
    #[cfg(test)]
    {
        CONTEXT.with(|state| f(&mut state.borrow_mut()))
    }
    #[cfg(not(test))]
    {
        f(&mut CONTEXT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
}
pub(crate) fn prepare_context(policy: &[u8], epoch: Option<&str>, cache: bool) {
    context(|state| {
        state.prepared = [
            Some(Sha256::digest(policy).into()),
            epoch.map(|v| Sha256::digest(v.as_bytes()).into()),
            Some(Sha256::digest([u8::from(cache)]).into()),
        ]
    });
}
pub(crate) struct TraversalContext<'a> {
    pub(crate) retained: Option<&'a str>,
    pub(crate) backfill: u64,
    pub(crate) active: Option<&'a str>,
    pub(crate) replay: Option<&'a str>,
    pub(crate) roots: &'a [PathBuf],
}
pub(crate) fn compare_context(observed: TraversalContext<'_>) -> Parts {
    context(|state| {
        let hash = |v: &str| Some(Sha256::digest(v.as_bytes()).into());
        let [policy, epoch, cache] = state.prepared;
        let parts = [
            Some(Sha256::digest(observed.backfill.to_be_bytes()).into()),
            hash(observed.active.unwrap_or("none")),
            policy,
            policy.map(|_| Sha256::digest([u8::from(epoch.is_some())]).into()),
            epoch,
            cache,
            hash(observed.replay.unwrap_or("none")),
        ];
        note(|counts| {
            counts.root_count = Some(observed.roots.len() as u64);
            if let Some((key, prior, roots)) = &state.retained {
                if Some(key.as_str()) == observed.retained {
                    let changed: [u64; 7] = std::array::from_fn(|i| {
                        u64::from(prior[i].zip(parts[i]).is_some_and(|(a, b)| a != b))
                    });
                    counts.traversal_context_change.merge(ContextChange {
                        backfill_changed: changed[0],
                        active_upload_context_changed: changed[1],
                        policy_changed: changed[2],
                        attribution_available_changed: changed[3],
                        attribution_epoch_changed: changed[4],
                        cache_capability_changed: changed[5],
                        replay_changed: changed[6],
                        roots_changed: u64::from(*roots != roots_digest(observed.roots)),
                    });
                }
            }
        });
        parts
    })
}
pub(crate) fn started_context(key: &str, parts: Parts, roots: &[PathBuf]) {
    context(|state| state.retained = Some((key.to_owned(), parts, roots_digest(roots))));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_comparisons_use_retained_start_and_same_count_ordered_roots() {
        context(|state| *state = ContextState::default());
        let roots = [PathBuf::from("/synthetic/a")];
        let other = [PathBuf::from("/synthetic/b")];
        let compare = |retained, backfill, active, replay, roots: &[PathBuf]| {
            compare_context(TraversalContext {
                retained,
                backfill,
                active,
                replay,
                roots,
            })
        };
        let scope = claude_reread::Scope::begin(true);
        prepare_context(b"policy-a", Some("epoch-a"), false);
        let parts = compare(
            Some("prior-process"),
            1,
            Some("a"),
            Some("replay-a"),
            &roots,
        );
        assert!(
            claude_reread::Counts::default()
                .with_current()
                .contract
                .traversal_context_change
                .is_empty(),
            "first process observation unknown"
        );
        started_context("first", parts, &roots);
        compare(Some("first"), 1, Some("a"), Some("replay-a"), &roots);
        compare(
            Some("first"),
            1,
            Some("a"),
            Some("replay-a"),
            &[PathBuf::from("/synthetic//./a/")],
        );
        prepare_context(b"policy-b", Some("epoch-b"), true);
        compare(Some("first"), 2, Some("b"), Some("replay-b"), &other);
        let changed = claude_reread::Counts::default()
            .with_current()
            .contract
            .traversal_context_change;
        assert_eq!(
            changed,
            ContextChange {
                backfill_changed: 1,
                active_upload_context_changed: 1,
                policy_changed: 1,
                attribution_available_changed: 0,
                attribution_epoch_changed: 1,
                cache_capability_changed: 1,
                replay_changed: 1,
                roots_changed: 1
            }
        );
        prepare_context(b"policy-a", None, false);
        compare(Some("first"), 1, Some("a"), Some("replay-a"), &roots);
        let counts = scope.finish().contract;
        assert_eq!(
            counts
                .traversal_context_change
                .attribution_available_changed,
            1
        );
        assert_eq!(
            counts.traversal_context_change.attribution_epoch_changed, 1,
            "unknown epoch adds no change"
        );
        assert_eq!(counts.root_count, Some(1));
        let scope = claude_reread::Scope::begin(true);
        let ordered = [roots[0].clone(), other[0].clone()];
        started_context("ordered", parts, &ordered);
        compare(Some("ordered"), 1, Some("a"), Some("replay-a"), &ordered);
        assert_eq!(
            claude_reread::Counts::default()
                .with_current()
                .contract
                .traversal_context_change
                .roots_changed,
            0
        );
        let reversed = [other[0].clone(), roots[0].clone()];
        compare(Some("ordered"), 1, Some("a"), Some("replay-a"), &reversed);
        compare(
            Some("unobserved"),
            1,
            Some("a"),
            Some("replay-a"),
            &reversed,
        );
        let ordered_counts = scope.finish().contract;
        assert_eq!(ordered_counts.traversal_context_change.roots_changed, 1);
        assert_eq!(ordered_counts.root_count, Some(2));
        let json = serde_json::to_string(&counts).unwrap();
        for forbidden in [
            "synthetic",
            "epoch-a",
            "epoch-b",
            "policy-a",
            "policy-b",
            "replay-a",
            "first",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
