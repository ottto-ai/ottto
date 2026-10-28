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
//! M1's named crash edges cannot stand in for the later edges; cheap/raw I/O
//! stays unmeasured until the acquisition owner supplies a real observation.
use crate::snapshots::{
    snapshot_semantic_envelope, SnapshotItem, SnapshotSource, SnapshotUploadPolicy,
};
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

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
    super::durable_tail::seed_pinned_v1(cache, source, key, index, pin)
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
}
impl CrashPoint {
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
    pub(crate) fn name(self) -> String {
        format!("{self:?}")
    }
}

/// A child acknowledges the exact edge durably, then actually dies. Only the
/// isolated child test sets these variables. Parent checks SIGKILL and marker.
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

/// Consumed bytes at the real BoundedJsonlReader::consume boundary, including
/// skipped lines and codec re-derivation readers. This is not an OS read counter:
/// prefetch, raw head reads and certificate samples are reported separately.
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
