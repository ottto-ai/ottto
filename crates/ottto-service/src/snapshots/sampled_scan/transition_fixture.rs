//! Minimal test-only mirror of E1/E4 #882 shared money oracle.
//! Exact types/comparator from origin/e4/transition-fixture; drop this mirror
//! when #882 merges. No independent comparator or normalization policy.
#![allow(dead_code)]
use crate::snapshots::{
    snapshot_semantic_envelope, SnapshotItem, SnapshotSource, SnapshotUploadPolicy,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Mode {
    ColdFull,
    Ram,
    DiskRestore,
    Restart,
    EvictRetry,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct IoBytes {
    pub(crate) consumed: u64,
    pub(crate) rederive_head: u64,
    pub(crate) rederive_named: u64,
    /// None is UNMEASURED, never a zero-byte receipt. Future acquisition seams
    /// must measure cheap checks/raw reads before claiming DoD 6/12 complete.
    pub(crate) cheap_checks: Option<u64>,
    pub(crate) other_reads: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Accepted {
    pub(crate) body: Value,
    pub(crate) witness: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RouteResult {
    pub(crate) mode: Mode,
    pub(crate) source: SnapshotSource,
    pub(crate) batches: Vec<Vec<u8>>,
    pub(crate) normalized: Value,
    pub(crate) snapshots: BTreeMap<String, Value>,
    pub(crate) accepted: BTreeMap<String, Accepted>,
    /// Codex drivers collect the REAL index applied/captured receipts, owner
    /// proofs and counting state. Empty only for sources without Codex state.
    pub(crate) codex_evidence: Value,
    pub(crate) io: IoBytes,
    pub(crate) modes: (usize, usize, usize),
    pub(crate) restored: u64,
}
impl RouteResult {
    /// Exact existing cross-build sentinel: only physical fingerprint and its
    /// two derived revision hashes may change. Verify typed/wire correspondence
    /// first, then recompute through production envelope functions.
    pub(crate) fn emitted(
        mode: Mode,
        source: SnapshotSource,
        batches: Vec<Vec<u8>>,
        items: &[SnapshotItem],
    ) -> Self {
        let mut seen = BTreeSet::new();
        let mut snapshots = BTreeMap::new();
        let envelopes = batches
            .iter()
            .map(|bytes| {
                let mut wire: Value = serde_json::from_slice(bytes).unwrap();
                assert_eq!(wire["source"], source.api_slug());
                for snapshot in wire["snapshots"].as_array_mut().expect("batch snapshots") {
                    let item = items
                        .iter()
                        .find(|item| snapshot["snapshot_fingerprint"] == item.snapshot_fingerprint)
                        .expect("wire snapshot has its production item");
                    assert!(
                        seen.insert(item.snapshot_fingerprint.clone()),
                        "duplicate emission"
                    );
                    let raw = snapshot.clone();
                    let mut fields = raw.as_object().unwrap().clone();
                    fields
                        .remove("semantic_envelope")
                        .expect("production envelope");
                    assert_eq!(Value::Object(fields), serde_json::to_value(item).unwrap());
                    let policy = SnapshotUploadPolicy::default();
                    assert_eq!(
                        raw["semantic_envelope"],
                        serde_json::to_value(snapshot_semantic_envelope(source, item, policy))
                            .unwrap()
                    );
                    let mut neutral = item.clone();
                    neutral.source_file_fingerprint = Some("physical-identity:excluded".into());
                    snapshot["source_file_fingerprint"] = json!(neutral.source_file_fingerprint);
                    snapshot["semantic_envelope"] =
                        serde_json::to_value(snapshot_semantic_envelope(source, &neutral, policy))
                            .unwrap();
                    let mut restored = snapshot.clone();
                    for path in [
                        "/source_file_fingerprint",
                        "/semantic_envelope/revision_hash",
                        "/semantic_envelope/revision_v2_hash",
                    ] {
                        *restored.pointer_mut(path).expect("existing sentinel path") =
                            raw.pointer(path).expect("existing raw path").clone();
                    }
                    assert_eq!(restored, raw, "normalization escaped sentinel scope");
                    assert!(
                        snapshots
                            .insert(item.source_session_id.clone(), snapshot.clone())
                            .is_none(),
                        "duplicate entity"
                    );
                }
                wire
            })
            .collect::<Vec<_>>();
        assert_eq!(seen.len(), items.len(), "every item must reach upload");
        Self {
            mode,
            source,
            batches,
            normalized: json!(envelopes),
            snapshots,
            accepted: BTreeMap::new(),
            codex_evidence: Value::Null,
            io: IoBytes::default(),
            modes: (0, 0, 0),
            restored: 0,
        }
    }
}

pub(crate) mod money_oracle {
    use super::*;
    const FIELDS: &[&str] = &[
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
        "reasoning_output_tokens",
        "unattributed_total_tokens",
        "request_count",
        "cost",
        "usage_buckets",
        "model_usage",
        "removed_usage",
        "removed_request_count",
        "usage_accounting_contract",
        "telemetry_owned_complete",
    ];

    /// Structural, per-field diagnostics even when the final bytes differ.
    pub(crate) fn diff(path: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
        if a == b {
            return;
        }
        match (a, b) {
            (Value::Object(a), Value::Object(b)) => {
                for key in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
                    diff(
                        &format!("{path}/{key}"),
                        a.get(key).unwrap_or(&Value::Null),
                        b.get(key).unwrap_or(&Value::Null),
                        out,
                    );
                    if a.contains_key(key) != b.contains_key(key) {
                        out.push(format!("{path}/{key}: field presence differs"));
                    }
                }
            }
            (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
                for (i, (a, b)) in a.iter().zip(b).enumerate() {
                    diff(&format!("{path}/{i}"), a, b, out);
                }
            }
            _ => out.push(format!("{path}: expected {a}, got {b}")),
        }
    }
    pub(crate) fn assert_equivalent(cold: &RouteResult, other: &RouteResult) {
        assert_eq!(cold.source, other.source);
        assert!(
            !cold.snapshots.is_empty(),
            "empty cold Full is no money proof"
        );
        let mut differences = Vec::new();
        if cold.source == SnapshotSource::Codex {
            for route in [cold, other] {
                for field in ["TierReplay", "token_count"] {
                    assert!(
                        route.codex_evidence.get(field).is_some(),
                        "{:?}: Codex evidence/{field} not collected",
                        route.mode
                    );
                }
            }
        }
        for entity in cold
            .snapshots
            .keys()
            .chain(other.snapshots.keys())
            .collect::<BTreeSet<_>>()
        {
            let (a, b) = (cold.snapshots.get(entity), other.snapshots.get(entity));
            match (a, b) {
                (Some(a), Some(b)) => {
                    for field in FIELDS {
                        diff(
                            &format!("entity/{entity}/{field}"),
                            &a[*field],
                            &b[*field],
                            &mut differences,
                        );
                    }
                }
                _ => differences.push(format!("entity/{entity}: missing/extra emitted entity")),
            }
        }
        diff(
            "codex/TierReplay_receipts_ownership_token_count",
            &cold.codex_evidence,
            &other.codex_evidence,
            &mut differences,
        );
        diff(
            "normalized_batch",
            &cold.normalized,
            &other.normalized,
            &mut differences,
        );
        assert!(
            differences.is_empty(),
            "{:?} vs {:?}:\n{}",
            cold.mode,
            other.mode,
            differences.join("\n")
        );
        assert_eq!(
            crate::canonical_json::canonicalize(&cold.normalized).unwrap(),
            crate::canonical_json::canonicalize(&other.normalized).unwrap(),
            "normalized bytes"
        );
    }

    /// `entity` is held in `other`; every emitted sibling must still equal cold.
    pub(crate) fn assert_held(
        entity: &str,
        prior: &RouteResult,
        other: &RouteResult,
        cold: &RouteResult,
    ) {
        assert!(
            !other.snapshots.contains_key(entity),
            "held entity emitted a body (including $0)"
        );
        let before = prior
            .accepted
            .get(entity)
            .expect("prior accepted body + witness");
        assert!(
            before.body["request_count"].as_u64().unwrap_or(0) > 0,
            "fixture must start with nonempty accepted money"
        );
        assert!(
            !before.witness.is_empty(),
            "fixture must have accepted witness"
        );
        assert_eq!(
            other.accepted.get(entity),
            Some(before),
            "held accepted body/witness changed"
        );
        let mut expected = cold.clone();
        expected.snapshots.remove(entity);
        let mut actual = other.clone();
        // Filter whole envelopes, preserving every field of each emitted sibling.
        for result in [&mut expected, &mut actual] {
            for envelope in result.normalized.as_array_mut().unwrap().iter_mut() {
                envelope["snapshots"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|s| s["source_session_id"] != entity);
            }
            result
                .normalized
                .as_array_mut()
                .unwrap()
                .retain(|e| !e["snapshots"].as_array().unwrap().is_empty());
        }
        if !expected.snapshots.is_empty() {
            assert_equivalent(&expected, &actual);
        } else {
            assert!(actual.snapshots.is_empty());
            assert_eq!(expected.normalized, actual.normalized);
        }
    }

    /// Caller supplies independently known extent/revision regression; money
    /// shrink is not inferred from tokens (legitimate corrections exist).
    pub(crate) fn assert_no_smaller_reemit(
        entity: &str,
        prior: &RouteResult,
        candidate: &RouteResult,
        cold: &RouteResult,
        behind_accepted: bool,
    ) {
        if behind_accepted {
            assert_held(entity, prior, candidate, cold);
        } else {
            assert_equivalent(cold, candidate);
        }
    }

    pub(crate) fn assert_quiet_restart_zero_bytes(result: &RouteResult) {
        assert!(matches!(
            result.mode,
            Mode::DiskRestore | Mode::Restart | Mode::EvictRetry
        ));
        assert_eq!(result.modes.0, 0, "quiet restart read Full");
        assert_eq!(
            result.io.consumed, 0,
            "actual parser consumed transcript bytes"
        );
        assert_eq!(result.io.rederive_head, 0, "card-F head bytes remain");
        assert_eq!(result.io.rederive_named, 0, "named-line bytes remain");
        assert_eq!(
            result.io.cheap_checks,
            Some(0),
            "cheap checks unmeasured/nonzero"
        );
        assert_eq!(
            result.io.other_reads,
            Some(0),
            "other I/O unmeasured/nonzero"
        );
        assert!(
            result.batches.is_empty(),
            "quiet restart emitted a new body"
        );
    }
}

/// Reuses the acquisition clock. This changes neither a process allowance nor
/// a daily budget: those owners must consume the same clock when implemented.
pub(crate) fn with_scan_clock<T>(now: u64, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            super::TEST_NOW.with(|clock| clock.set(self.0));
        }
    }
    let _reset = Reset(super::TEST_NOW.with(|clock| clock.replace(Some(now))));
    run()
}

/// Snapshots only real native state supplied by a caller, including empty
/// values. No disk reads, fabricated debt, ACK, or new authority. Call before
/// and after the held finish path, then compare the relevant fields exactly.
pub(crate) fn native_effects(
    index: &super::super::ScanIndex,
    scan: &super::super::SourceScanResult,
) -> Value {
    json!({
        "files": index.files,
        "accepted": index.accepted_snapshot_fingerprints,
        "parent_ledgers": index.codex_parent_ownership_ledgers,
        "parent_refs": index.codex_parent_ownership_refs,
        "proofs": index.codex_parent_prefix_proofs,
        "proof_seq": index.codex_parent_proof_seq,
        "proof_parents_live": index.codex_parent_proof_parents_live,
        "side": index.codex_parent_side,
        "side_generation": index.codex_parent_side_generation,
        "side_requests": index.codex_parent_side_requests,
        "blocked": index.codex_state_only_blocked_session_ids,
        "blocked_by_file": index.codex_state_only_blocked_by_file,
        "pending_finalizations": scan.pending_finalization.len(),
        "witnesses": scan.snapshots.iter().map(|item|
            (item.source_session_id.clone(),
             super::super::snapshot_upload_body_witness(item)))
            .collect::<BTreeMap<_, _>>(),
        "census": {
            "complete": scan.census_complete,
            "state_complete": scan.state_census_complete,
            "sidecar_complete": scan.sidecar_census_complete,
            "sessions": scan.scanned_session_count,
            "ownership_incomplete": scan.ownership_incomplete_file_count,
            "terminal_ownership_incomplete": scan.terminal_ownership_incomplete_file_count,
            "residue_keys": scan.census_residue_index_key_count,
            "residue_blocked": scan.census_residue_blocked_session_count,
            "residue_archived": scan.census_residue_archived_rollout_count,
        },
    })
}

/// A scoped error at a REAL store call. Install on the worker thread. Existing
/// rename/dir-sync hooks are preserved. Reaching the nth edge is mandatory:
/// callers assert hits(), so an unvisited injection cannot pass as a hold.
pub(crate) struct StoreFailure {
    previous: Option<crate::durable_tail_store::test_hooks::TransitionHook>,
    hits: std::rc::Rc<Cell<usize>>,
}
impl StoreFailure {
    pub(crate) fn hits(&self) -> usize {
        self.hits.get()
    }
}
impl Drop for StoreFailure {
    fn drop(&mut self) {
        crate::durable_tail_store::test_hooks::replace_transition_hook(self.previous.take());
    }
}
pub(crate) fn fail_store_at(point: CrashPoint, nth: usize) -> StoreFailure {
    assert!(nth > 0);
    assert!(matches!(
        point,
        CrashPoint::BeforeDirectoryCreate
            | CrashPoint::DirectoryCreated
            | CrashPoint::BeforeRename
            | CrashPoint::BeforeDirectorySync
            | CrashPoint::BeforeRetireUnlink
            | CrashPoint::RetiredUnlink
            | CrashPoint::BeforeRetireSync
            | CrashPoint::RetiredSynced
    ));
    let hits = std::rc::Rc::new(Cell::new(0_usize));
    let count = std::rc::Rc::clone(&hits);
    let previous = crate::durable_tail_store::test_hooks::replace_transition_hook(Some(Box::new(
        move |reached, _| {
            if reached == point {
                let n = count.get().checked_add(1).expect("edge counter overflow");
                count.set(n);
                if n == nth {
                    return Err(std::io::Error::other(format!("injected {point:?}")));
                }
            }
            Ok(())
        },
    )));
    StoreFailure { previous, hits }
}

#[test]
fn scan_clock_restores_after_nested_scope_and_unwind() {
    with_scan_clock(100, || {
        assert_eq!(super::now_seconds(), 100);
        with_scan_clock(200, || assert_eq!(super::now_seconds(), 200));
        assert_eq!(super::now_seconds(), 100);
        assert!(std::panic::catch_unwind(|| with_scan_clock(300, || panic!("cancel"))).is_err());
        assert_eq!(super::now_seconds(), 100);
    });
}

#[test]
fn transition_failure_restores_outer_hook_after_unwind() {
    use crate::durable_tail_store::test_hooks;
    let outer = fail_store_at(CrashPoint::BeforeDirectoryCreate, 2);
    assert!(std::panic::catch_unwind(|| {
        let inner = fail_store_at(CrashPoint::BeforeDirectoryCreate, 1);
        assert!(test_hooks::transition_edge(
            CrashPoint::BeforeDirectoryCreate,
            Path::new("synthetic")
        )
        .is_err());
        assert_eq!(inner.hits(), 1);
        panic!("cancel");
    })
    .is_err());
    assert_eq!(outer.hits(), 0);
    assert!(
        test_hooks::transition_edge(CrashPoint::BeforeDirectoryCreate, Path::new("synthetic"))
            .is_ok()
    );
    assert!(
        test_hooks::transition_edge(CrashPoint::BeforeDirectoryCreate, Path::new("synthetic"))
            .is_err()
    );
    assert_eq!(outer.hits(), 2);
}

/// Protect the existing matrix while publishing new names for owners. This
/// checks vocabulary only; it is not evidence that live call sites execute.
#[test]
fn crash_extension_names_are_disjoint_from_the_m1_matrix() {
    let mut names = BTreeSet::new();
    for point in CrashPoint::ALL
        .into_iter()
        .chain(CrashPoint::STORE_EXTENSION)
        .chain(CrashPoint::LIVE_EXTENSION)
    {
        assert!(names.insert(point.name()), "duplicate boundary {point:?}");
    }
    assert_eq!(names.len(), 32);
    assert!(names.contains("BeforeCodexPublication"));
}
