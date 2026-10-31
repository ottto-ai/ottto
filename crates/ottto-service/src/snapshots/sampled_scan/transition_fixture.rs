//! Shared test-only transition vocabulary and emitted-money oracle.
//!
//! Drivers must use native scanning, upload/ACK and the one durable store.
//! M1 writes AFTER index save; `Receipt` below does not imply write-ahead.
//! New slice drivers supply their native order rather than changing this oracle.
//!
//! Extension rows (keep the one comparator):
//! - 5b: stale selection clear (#859), finite revision candidates (record's own
//!   applied revision, current active revision, revisions explicitly retained
//!   by the index; exactly one match), scope barriers and accepted-body floor.
//! - a0: direct restore with cache admission refused, active lease/cap pressure,
//!   pending receipt reconciliation and directory creation/parent-sync edges.
//! - a1: live preparation/finish success/error and receipt BEFORE publication.
//! - audit gate: quiet/append after 1h/50h and >256 slots, clock/debt controls.
//! - E2: protected nonempty TierReplay, group/EOF/archive and cursor custody.
//!
//! M1's named crash edges cannot stand in for the later edges; cheap/raw I/O
//! stays unmeasured until the acquisition owner supplies a real observation.
use crate::snapshots::{
    snapshot_semantic_envelope, SnapshotItem, SnapshotSource, SnapshotUploadPolicy,
};
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Emitted-body comparison for native scan fixtures without a transport driver.
pub(crate) fn scan_money(
    source: SnapshotSource,
    index: &super::super::ScanIndex,
    scan: &super::super::SourceScanResult,
) -> RouteResult {
    let batches = if scan.snapshots.is_empty() {
        Vec::new()
    } else {
        let mut request = super::super::tests::valid_v6_batch_request();
        request.source = source.api_slug().into();
        request.snapshots = scan.snapshots.clone();
        vec![serde_json::to_vec(&request).unwrap()]
    };
    let mut route = RouteResult::emitted(Mode::Ram, source, batches, &scan.snapshots);
    if source == SnapshotSource::Codex {
        route.codex_evidence = codex_evidence(index, scan);
    }
    route
}

/// The actual post-scan tier/ownership state and emitted token counts. Shared
/// by ordinary scan and durable-transition adapters; absence is collected too.
pub(crate) fn codex_evidence(
    index: &super::super::ScanIndex,
    scan: &super::super::SourceScanResult,
) -> Value {
    json!({
        "TierReplay": index.files.iter().map(|(key, entry)| (key.clone(), json!({
            "applied": entry.codex_applied_tier_receipt,
            "required": entry.codex_applied_tier_receipt_required,
            "captured": entry.codex_captured_tier_receipt,
            "owner": entry.codex_protected_owner,
            "v2": entry.codex_counting_v2,
        }))).collect::<BTreeMap<_, _>>(),
        "token_count": scan.snapshots.iter().map(|item| (item.source_session_id.clone(), json!([
            item.input_tokens, item.output_tokens, item.cache_read_tokens,
            item.reasoning_output_tokens, item.request_count,
        ]))).collect::<BTreeMap<_, _>>(),
    })
}

/// Keep private acquisition internals private; sibling test adapters enter here.
pub(crate) fn local_key(path: &Path) -> String {
    super::super::local_index_key(path)
}
pub(crate) fn seed_old_writer(
    cache: &super::SharedCache,
    source: SnapshotSource,
    key: &str,
    index: &super::super::ScanIndex,
    pin: &str,
) -> Vec<u8> {
    super::durable_tail::transition_seed::seed_pinned_v1(cache, source, key, index, pin)
}

/// The production body allowlist, without exposing the private codec module.
pub(crate) fn allowlist_digest(source: SnapshotSource) -> [u8; 32] {
    super::super::sampled_jsonl::durable::allowlist_digest(source)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Mode {
    ColdFull,
    Ram,
    DiskRestore,
    Restart,
    EvictRetry,
}

/// Logical boundaries use `reach`; physical M1 boundaries use the store's
/// existing before-rename and before-directory-sync hooks. No fake fsyncs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CrashPoint {
    OldWriter,
    Restore,
    Tail,
    BeforeAck,
    AfterAck,
    BeforeIndexSave,
    AfterIndexSave,
    BeforeTempWrite,
    TempWritten,
    FileSynced,
    BeforeRename,
    BeforeDirectorySync,
    Receipt,
    SaveGc,
    RestartOne,
    RestartTwo,
    BeforeDirectoryCreate,
    DirectoryCreated,
    BeforeParentSync,
    ParentSynced,
    BeforePrepare,
    Prepared,
    BeforeNativeFinish,
    NativeFinishOk,
    NativeFinishError,
    BeforeRetireUnlink,
    RetiredUnlink,
    BeforeRetireSync,
    RetiredSynced,
    BeforeNativeEffects,
    AfterNativeEffects,
    BeforeCodexPublication,
}
impl CrashPoint {
    // Preserve the existing M1 executable matrix. Later points must not be
    // appended here until its child driver actually traverses those paths.
    pub(crate) const ALL: [Self; 16] = [
        Self::OldWriter,
        Self::Restore,
        Self::Tail,
        Self::BeforeAck,
        Self::AfterAck,
        Self::BeforeIndexSave,
        Self::AfterIndexSave,
        Self::BeforeTempWrite,
        Self::TempWritten,
        Self::FileSynced,
        Self::BeforeRename,
        Self::BeforeDirectorySync,
        Self::Receipt,
        Self::SaveGc,
        Self::RestartOne,
        Self::RestartTwo,
    ];
    /// Additional physical store edges wired on this fixture branch. The
    /// retirement edges refer to classified remove_keys, never temp cleanup.
    pub(crate) const STORE_EXTENSION: [Self; 6] = [
        Self::BeforeDirectoryCreate,
        Self::DirectoryCreated,
        Self::BeforeRetireUnlink,
        Self::RetiredUnlink,
        Self::BeforeRetireSync,
        Self::RetiredSynced,
    ];
    /// Names reserved for the owning a0/a1/E2 call sites. They are NOT a
    /// runnable matrix on M1; reach() must be placed at the real boundaries.
    pub(crate) const LIVE_EXTENSION: [Self; 10] = [
        Self::BeforeParentSync,
        Self::ParentSynced,
        Self::BeforePrepare,
        Self::Prepared,
        Self::BeforeNativeFinish,
        Self::NativeFinishOk,
        Self::NativeFinishError,
        Self::BeforeNativeEffects,
        Self::AfterNativeEffects,
        Self::BeforeCodexPublication,
    ];
    pub(crate) fn name(self) -> String {
        format!("{self:?}")
    }
}

// A child acknowledges the exact edge durably, then actually dies. Only the
// isolated child test sets these variables. Parent checks SIGKILL and marker.
thread_local! { static CRASH_ARMED: Cell<bool> = const { Cell::new(false) }; }
pub(crate) fn arm_crashes() {
    CRASH_ARMED.with(|armed| armed.set(true));
}
pub(crate) fn reach(point: CrashPoint) {
    if !CRASH_ARMED.with(Cell::get) {
        return;
    }
    let name = point.name();
    if std::env::var("OTTTO_TRANSITION_CRASH").ok().as_deref() != Some(name.as_str()) {
        return;
    }
    let marker = std::env::var_os("OTTTO_TRANSITION_MARKER").expect("child marker");
    let mut file = std::fs::File::create(marker).unwrap();
    use std::io::Write;
    file.write_all(name.as_bytes()).unwrap();
    file.sync_all().unwrap();
    // SAFETY: raise has no pointer/ownership preconditions; only this child dies.
    unsafe {
        libc::raise(libc::SIGKILL);
    }
    panic!("SIGKILL unexpectedly returned");
}

// Consumed bytes at the real BoundedJsonlReader::consume boundary, including
// skipped lines and codec re-derivation readers. This is not an OS read counter:
// prefetch, raw head reads and certificate samples are reported separately.
thread_local! { static CONSUMED: Cell<Option<u64>> = const { Cell::new(None) }; }
pub(crate) fn record_consumed(bytes: u64) {
    CONSUMED.with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + bytes));
        }
    });
}
pub(crate) fn observe_consumed<T>(f: impl FnOnce() -> T) -> (T, u64) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CONSUMED.with(|c| c.set(None));
        }
    }
    CONSUMED.with(|c| assert!(c.replace(Some(0)).is_none(), "nested byte observer"));
    let _reset = Reset;
    let result = f();
    let bytes = CONSUMED.with(|c| c.get().unwrap());
    (result, bytes)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct IoBytes {
    pub(crate) consumed: u64,
    pub(crate) rederive_head: u64,
    pub(crate) rederive_named: u64,
    /// None is UNMEASURED, never a zero-byte receipt. Future acquisition seams
    /// must measure cheap checks/raw reads before claiming DoD 6/12 complete.
    pub(crate) cheap_checks: Option<u64>,
    /// Head/boundary identity hashes detect mtime-restored replacement. These
    /// are separate from body/fragment re-derivation and other cheap/raw reads;
    /// None is unmeasured, not zero. Quiet callers must supply the exact window.
    pub(crate) anchor_reads: Option<u64>,
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

/// Slices implement this over their native pipeline, not an alternate parser.
/// `emit_bodies` starts from the same accepted index in all five routes.
pub(crate) trait TransitionDriver {
    fn emit_bodies(&mut self, mode: Mode) -> RouteResult;
    fn save_gc(&mut self, mode: Mode);
    fn restart(&mut self);
}

pub(crate) fn assert_child_killed(
    status: std::process::ExitStatus,
    marker: &Path,
    point: CrashPoint,
) {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "child did not die at {point:?}"
    );
    assert_eq!(std::fs::read_to_string(marker).unwrap(), point.name());
}

pub(crate) mod money_oracle {
    use super::*;
    pub(crate) const FIELDS: &[&str] = &[
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
        assert_quiet_restart_with_anchor_window(result, 0);
    }

    /// Identity head/boundary hashes are required to detect mtime-restored
    /// replacement, not a body/fragment read leak. Permit exactly the caller's
    /// computed anchor window for this assertion only; all body/other bytes
    /// remain forbidden. The default zero-byte assertion passes a zero window.
    pub(crate) fn assert_quiet_restart_with_anchor_window(
        result: &RouteResult,
        anchor_window: u64,
    ) {
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
            result.io.anchor_reads,
            Some(anchor_window),
            "identity anchor I/O unmeasured or outside exact window"
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

    #[cfg(test)]
    mod quiet_tests {
        use super::*;

        // Synthetic measured I/O premises exercise the shared assertion; these
        // unit controls do not claim that a native scan measured these bytes.
        const ANCHOR_WINDOW: u64 = 8192;

        fn quiet_result(anchor_reads: u64) -> RouteResult {
            let mut result =
                RouteResult::emitted(Mode::Restart, SnapshotSource::ClaudeCode, Vec::new(), &[]);
            result.io = IoBytes {
                cheap_checks: Some(0),
                anchor_reads: Some(anchor_reads),
                other_reads: Some(0),
                ..IoBytes::default()
            };
            result
        }

        #[test]
        fn quiet_default_accepts_zero_anchor_reads() {
            assert_quiet_restart_zero_bytes(&quiet_result(0));
        }

        #[test]
        #[should_panic(expected = "identity anchor I/O unmeasured or outside exact window")]
        fn quiet_default_rejects_anchor_reads() {
            assert_quiet_restart_zero_bytes(&quiet_result(ANCHOR_WINDOW));
        }

        #[test]
        fn quiet_anchor_window_accepts_exact_count() {
            assert_quiet_restart_with_anchor_window(&quiet_result(ANCHOR_WINDOW), ANCHOR_WINDOW);
        }

        #[test]
        #[should_panic(expected = "identity anchor I/O unmeasured or outside exact window")]
        fn quiet_anchor_window_rejects_short_count() {
            assert_quiet_restart_with_anchor_window(
                &quiet_result(ANCHOR_WINDOW - 1),
                ANCHOR_WINDOW,
            );
        }

        #[test]
        #[should_panic(expected = "identity anchor I/O unmeasured or outside exact window")]
        fn quiet_anchor_window_rejects_excess_count() {
            assert_quiet_restart_with_anchor_window(
                &quiet_result(ANCHOR_WINDOW + 1),
                ANCHOR_WINDOW,
            );
        }

        #[test]
        fn quiet_anchor_window_rejects_body_bytes() {
            let baseline = quiet_result(ANCHOR_WINDOW);
            for io in [
                IoBytes {
                    consumed: 1,
                    ..baseline.io.clone()
                },
                IoBytes {
                    rederive_head: 1,
                    ..baseline.io.clone()
                },
                IoBytes {
                    rederive_named: 1,
                    ..baseline.io.clone()
                },
            ] {
                let mut changed = baseline.clone();
                changed.io = io;
                assert!(std::panic::catch_unwind(|| {
                    assert_quiet_restart_with_anchor_window(&changed, ANCHOR_WINDOW);
                })
                .is_err());
            }
        }

        #[test]
        #[should_panic(expected = "other I/O unmeasured/nonzero")]
        fn quiet_anchor_window_rejects_other_reads() {
            let mut result = quiet_result(ANCHOR_WINDOW);
            result.io.other_reads = Some(1);
            assert_quiet_restart_with_anchor_window(&result, ANCHOR_WINDOW);
        }

        #[test]
        #[should_panic(expected = "identity anchor I/O unmeasured or outside exact window")]
        fn quiet_anchor_window_rejects_unmeasured_anchors() {
            let mut result = quiet_result(ANCHOR_WINDOW);
            result.io.anchor_reads = None;
            assert_quiet_restart_with_anchor_window(&result, ANCHOR_WINDOW);
        }
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

/// Read native ACK membership without granting or copying it into another index.
pub(crate) fn accepted_fingerprints(index: &super::super::ScanIndex) -> &BTreeSet<String> {
    &index.accepted_snapshot_fingerprints
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
