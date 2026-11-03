//! Shared test-only transition vocabulary and emitted-money oracle.
//!
//! Drivers must use native scanning and upload/ACK. New drivers supply their
//! native order rather than changing this oracle. Cheap/raw I/O stays
//! unmeasured until the acquisition owner supplies a real observation.
use crate::snapshots::{
    snapshot_semantic_envelope, SnapshotItem, SnapshotSource, SnapshotUploadPolicy,
};
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

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
    codex_evidence_of_items(index, &scan.snapshots)
}

/// [`codex_evidence`] for a driver that holds the emitted items without a
/// scan result (the Tail transition rows' native finishes).
pub(crate) fn codex_evidence_of_items(
    index: &super::super::ScanIndex,
    items: &[SnapshotItem],
) -> Value {
    json!({
        "TierReplay": index.files.iter().map(|(key, entry)| (key.clone(), json!({
            "applied": entry.codex_applied_tier_receipt,
            "required": entry.codex_applied_tier_receipt_required,
            "captured": entry.codex_captured_tier_receipt,
            "owner": entry.codex_protected_owner,
            "v2": entry.codex_counting_v2,
        }))).collect::<BTreeMap<_, _>>(),
        "token_count": items.iter().map(|item| (item.source_session_id.clone(), json!([
            item.input_tokens, item.output_tokens, item.cache_read_tokens,
            item.reasoning_output_tokens, item.request_count,
        ]))).collect::<BTreeMap<_, _>>(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Mode {
    ColdFull,
    Ram,
    DiskRestore,
    Restart,
    EvictRetry,
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
    /// Observed destination ledger by entity AFTER stored-body ACK; None for scan-only drivers.
    pub(crate) accepted_identity_buckets: Option<Value>,
    /// Codex drivers collect the REAL index applied/captured receipts, owner
    /// proofs and counting state. Empty only for sources without Codex state.
    pub(crate) codex_evidence: Value,
    pub(crate) io: IoBytes,
    pub(crate) modes: (usize, usize, usize),
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
        Self::emitted_under(
            mode,
            source,
            batches,
            items,
            SnapshotUploadPolicy::default(),
        )
    }
    /// `emitted` for a page the upload filter applied `policy` to.
    pub(crate) fn emitted_under(
        mode: Mode,
        source: SnapshotSource,
        batches: Vec<Vec<u8>>,
        items: &[SnapshotItem],
        policy: SnapshotUploadPolicy,
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
            accepted_identity_buckets: None,
            codex_evidence: Value::Null,
            io: IoBytes::default(),
            modes: (0, 0, 0),
        }
    }
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
        assert_placement_equivalent(cold, other);
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

    // Placement oracle: keep this block beside the existing totals comparator.
    const COUNTS: &[&str] = &[
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
        "reasoning_output_tokens",
        "unattributed_total_tokens",
        "request_count",
    ];
    const COSTS: &[&str] = &[
        "cost_usd",
        "input_cost_usd",
        "output_cost_usd",
        "cache_read_cost_usd",
        "cache_creation_cost_usd",
    ];

    fn placement_row(row: &Value, evidence: &Value) -> Value {
        let mut row = row.clone();
        let fields = row.as_object_mut().expect("placement row object");
        if let Some(reference) = fields.remove("evidence_ref") {
            let index = reference
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .expect("integer evidence_ref");
            let resolved = evidence
                .as_array()
                .and_then(|entries| entries.get(index))
                .filter(|entry| entry.is_object())
                .expect("unresolved evidence_ref");
            fields.insert("resolved_evidence".into(), resolved.clone());
        }
        if let Some(parts) = fields.get_mut("identity_parts") {
            let parts = parts.as_array_mut().expect("identity_parts array");
            assert!(!parts.is_empty(), "empty identity_parts");
            *parts = parts
                .iter()
                .map(|part| placement_row(part, evidence))
                .collect();
            parts.sort_by_key(Value::to_string);
        }
        row
    }

    fn assert_row_conserved(row: &Value) {
        let Some(parts) = row.get("identity_parts") else {
            return;
        };
        let parts = parts.as_array().expect("identity_parts array");
        // Missing evidence is an explicit untagged part, never invented account
        // credit or a silently computed residual that would mask lost shares.
        for field in COUNTS {
            let total = row[*field].as_u64().unwrap_or(0) as u128;
            let sum: u128 = parts
                .iter()
                .map(|part| part[*field].as_u64().expect("part counter present") as u128)
                .sum();
            assert_eq!(sum, total, "placement conservation/{field}");
        }
        for field in COSTS {
            let amount = |value: &Value| {
                let text = value.as_str().expect("present cost string");
                let (picos, rounded) =
                    super::super::super::parse_pi_usd_picos(text).expect("valid cost decimal");
                assert!(!rounded, "sub-pico placement cost");
                picos
            };
            match row.get(*field) {
                None => assert!(
                    parts.iter().all(|part| part.get(*field).is_none()),
                    "placement conservation/{field}: absent row cost has priced parts"
                ),
                Some(total) => {
                    let sum = parts
                        .iter()
                        .try_fold(0u128, |sum, part| {
                            sum.checked_add(amount(part.get(*field).expect("priced part")))
                        })
                        .expect("placement cost sum overflow");
                    assert_eq!(sum, amount(total), "placement conservation/{field}");
                }
            }
        }
    }

    fn placement_snapshot(snapshot: &Value) -> Value {
        let evidence = &snapshot["request_evidence"];
        let rows = |rows: &Value| -> Value {
            json!(rows
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| {
                    assert_row_conserved(row);
                    placement_row(row, evidence)
                })
                .collect::<Vec<_>>())
        };
        let mut entries = evidence.as_array().cloned().unwrap_or_default();
        entries.sort_by_key(Value::to_string);
        json!({
            "session_account_evidence": snapshot.get("session_account_evidence"),
            "request_evidence": entries,
            "request_identity_refusals": snapshot.get("request_identity_refusals"),
            "model_usage": rows(&snapshot["model_usage"]),
            "usage_buckets": snapshot["usage_buckets"].as_array().into_iter().flatten()
                .map(|bucket| json!({"bucket_start": bucket["bucket_start"],
                    "model_usage": rows(&bucket["model_usage"])})).collect::<Vec<_>>()
        })
    }

    /// Compare account AND organization placement for every counter/cost in
    /// every emitted entity. Evidence indexes are local to a body; resolve them
    /// before comparing. All row fields survive, including billing dimensions,
    /// retained/copy-invalidated markers and each untagged share.
    /// ACK drivers attach the actual destination ledger, never a replay inferred
    /// from emitted bodies. Scan-only drivers cannot prove post-ACK equivalence.
    pub(crate) fn assert_placement_equivalent(cold: &RouteResult, other: &RouteResult) {
        assert_eq!(cold.source, other.source);
        assert!(
            !cold.snapshots.is_empty(),
            "empty cold Full is no placement proof"
        );
        let mut differences = Vec::new();
        for entity in cold
            .snapshots
            .keys()
            .chain(other.snapshots.keys())
            .collect::<BTreeSet<_>>()
        {
            match (cold.snapshots.get(entity), other.snapshots.get(entity)) {
                (Some(a), Some(b)) => diff(
                    &format!("placement/entity/{entity}"),
                    &placement_snapshot(a),
                    &placement_snapshot(b),
                    &mut differences,
                ),
                _ => differences.push(format!("placement/entity/{entity}: missing/extra entity")),
            }
        }
        // Presence matters: a route must not silently lose ACK observations.
        assert_eq!(
            cold.accepted_identity_buckets.is_some(),
            other.accepted_identity_buckets.is_some(),
            "post-ACK placement observation missing on one route"
        );
        if let (Some(a), Some(b)) = (
            &cold.accepted_identity_buckets,
            &other.accepted_identity_buckets,
        ) {
            for entity in cold.snapshots.keys() {
                // Held entities are checked by assert_held; compare only emitted
                // siblings here, exactly like the body portion of this oracle.
                let (a, b) = (a.get(entity), b.get(entity));
                assert!(
                    a.is_some() && b.is_some(),
                    "post-ACK entity observation missing: {entity}"
                );
                diff(
                    &format!("placement/accepted_identity_buckets/{entity}"),
                    a.unwrap(),
                    b.unwrap(),
                    &mut differences,
                );
            }
        }
        assert!(
            differences.is_empty(),
            "{:?} vs {:?}:\n{}",
            cold.mode,
            other.mode,
            differences.join("\n")
        );
    }

    #[cfg(test)]
    mod placement_tests {
        use super::*;
        use crate::snapshots::claude_request_identity::{AcceptedBuckets, COLLECTOR};

        // Synthetic emitted requests in time order: A, switch to B, side call
        // under B, then an evidence gap. Independent weights expose any move.
        fn placement_fixture() -> RouteResult {
            let evidence = json!([
                {"identity_basis":"telemetry_login", "provider_workspace_hash":"c".repeat(64)},
                {"identity_basis":"telemetry_login", "provider_workspace_hash":"d".repeat(64)}
            ]);
            let share = |weight: u64, account: Option<(&str, u64)>| {
                let mut row = json!({});
                for (i, field) in COUNTS.iter().enumerate() {
                    row[*field] = json!(weight * (i as u64 + 1));
                }
                for field in COSTS {
                    row[*field] = json!(format!("0.{weight:06}"));
                }
                if let Some((account, reference)) = account {
                    row["account_identifier_hash"] = json!(account.repeat(64));
                    row["evidence_ref"] = json!(reference);
                }
                row
            };
            let main_parts = vec![
                share(1, Some(("a", 0))),
                share(2, Some(("b", 1))),
                share(4, None),
            ];
            let row = |weight, parts: Option<Vec<Value>>, account| {
                let mut row = share(weight, account);
                row["model"] = json!("claude-synthetic");
                row["auth_mode"] = json!("api_key");
                row["billing_channel"] = json!("api");
                row["billing_provider"] = json!("anthropic");
                row["subscription_product"] = json!("synthetic");
                if let Some(parts) = parts {
                    row["identity_parts"] = json!(parts);
                }
                row
            };
            let main = row(7, Some(main_parts.clone()), None);
            let side = row(3, None, Some(("b", 1)));
            let mut snapshots = BTreeMap::new();
            for (entity, total, requests) in [
                ("main", main, main_parts),
                ("side-call", side.clone(), vec![side]),
            ] {
                snapshots.insert(entity.to_string(), json!({
                    "source_session_id": entity,
                    "provenance": {"collector": COLLECTOR},
                    "session_account_evidence": {"account_identifier_hash":"a".repeat(64),
                        "provider_workspace_hash":"c".repeat(64), "identity_disposition":"creator"},
                    "request_evidence": evidence,
                    "request_identity_refusals": u64::from(entity == "main"),
                    "model_usage": [total],
                    "usage_buckets": requests.into_iter().enumerate().map(|(i, mut request)| {
                        request["model"] = json!("claude-synthetic");
                        let hour = if entity == "side-call" { 2 } else if i == 2 { 3 } else { i };
                        json!({"bucket_start": format!("2026-10-31T0{hour}:00:00Z"), "model_usage":[request]})
                    }).collect::<Vec<_>>()
                }));
            }
            let mut accepted = AcceptedBuckets::for_test();
            for snapshot in snapshots.values() {
                accepted.record(snapshot);
            }
            let ledger = snapshots
                .keys()
                .map(|entity| {
                    let state = serde_json::to_value(accepted.get(entity).unwrap()).unwrap();
                    assert!(
                        !state["shares"].as_array().unwrap().is_empty(),
                        "nonvacuous accepted shares"
                    );
                    (entity.clone(), state)
                })
                .collect::<BTreeMap<_, _>>();
            let mut result =
                RouteResult::emitted(Mode::ColdFull, SnapshotSource::ClaudeCode, vec![], &[]);
            result.snapshots = snapshots;
            result.accepted_identity_buckets = Some(json!(ledger));
            result
        }

        /// [money] Placement detects account/org/share/ACK corruption despite identical totals.
        #[test]
        fn money_oracle_placement_positive_control() {
            let cold = placement_fixture();
            let tagged = &cold.snapshots["main"]["model_usage"][0]["identity_parts"][0];
            assert_eq!(tagged["account_identifier_hash"], "a".repeat(64));
            for mode in [
                Mode::Ram,
                Mode::DiskRestore,
                Mode::Restart,
                Mode::EvictRetry,
            ] {
                let mut route = cold.clone();
                route.mode = mode;
                assert_equivalent(&cold, &route);
                // Reindex evidence and reverse parts without changing placement.
                for snapshot in route.snapshots.values_mut() {
                    snapshot["request_evidence"]
                        .as_array_mut()
                        .unwrap()
                        .reverse();
                    for row in snapshot["model_usage"].as_array_mut().unwrap() {
                        if let Some(parts) =
                            row.get_mut("identity_parts").and_then(Value::as_array_mut)
                        {
                            for part in parts.iter_mut() {
                                if let Some(n) = part["evidence_ref"].as_u64() {
                                    part["evidence_ref"] = json!(1 - n);
                                }
                            }
                            parts.reverse();
                        }
                        if let Some(n) = row["evidence_ref"].as_u64() {
                            row["evidence_ref"] = json!(1 - n);
                        }
                    }
                    for bucket in snapshot["usage_buckets"].as_array_mut().unwrap() {
                        for row in bucket["model_usage"].as_array_mut().unwrap() {
                            if let Some(n) = row["evidence_ref"].as_u64() {
                                row["evidence_ref"] = json!(1 - n);
                            }
                        }
                    }
                }
                assert_placement_equivalent(&cold, &route);
            }
            let mutations = [
                (
                    "/model_usage/0/identity_parts/0/account_identifier_hash",
                    json!("b".repeat(64)),
                ),
                ("/model_usage/0/identity_parts/0/evidence_ref", json!(1)),
                (
                    "/request_evidence/0/provider_workspace_hash",
                    json!("e".repeat(64)),
                ),
                ("/model_usage/0/identity_parts/0/input_tokens", json!(9)),
                (
                    "/model_usage/0/identity_parts/0/cost_usd",
                    json!("0.000009"),
                ),
                (
                    "/usage_buckets/0/model_usage/0/account_identifier_hash",
                    json!("b".repeat(64)),
                ),
                ("/request_identity_refusals", json!(0)),
            ];
            for (path, value) in mutations {
                let mut wrong = cold.clone();
                let snapshot = wrong.snapshots.get_mut("main").unwrap();
                *snapshot.pointer_mut(path).unwrap() = value;
                assert!(
                    std::panic::catch_unwind(|| assert_placement_equivalent(&cold, &wrong))
                        .is_err(),
                    "{path}"
                );
            }
            for field in [
                "identity_retained",
                "copy_invalidated",
                "auth_mode",
                "billing_channel",
                "billing_provider",
                "subscription_product",
            ] {
                let mut wrong = cold.clone();
                wrong.snapshots.get_mut("main").unwrap()["model_usage"][0][field] =
                    json!("changed");
                assert!(
                    std::panic::catch_unwind(|| assert_placement_equivalent(&cold, &wrong))
                        .is_err(),
                    "{field}"
                );
            }
            for field in COUNTS.iter().chain(COSTS) {
                let mut wrong = cold.clone();
                wrong.snapshots.get_mut("main").unwrap()["model_usage"][0]["identity_parts"][0]
                    [*field] = if COUNTS.contains(field) {
                    json!(99)
                } else {
                    json!("0.000099")
                };
                assert!(
                    std::panic::catch_unwind(|| assert_placement_equivalent(&wrong, &wrong))
                        .is_err(),
                    "conservation/{field}"
                );
            }
            let mut wrong = cold.clone();
            wrong.accepted_identity_buckets = Some(json!({"main": {}, "side-call": {}}));
            assert!(
                std::panic::catch_unwind(|| assert_placement_equivalent(&cold, &wrong)).is_err()
            );
            wrong.accepted_identity_buckets = None;
            assert!(
                std::panic::catch_unwind(|| assert_placement_equivalent(&cold, &wrong)).is_err()
            );
            // Even identical routes must fail if their shared allocator lost a
            // part: conservation is checked against each row's own totals.
            let mut wrong = cold.clone();
            wrong.snapshots.get_mut("main").unwrap()["model_usage"][0]["identity_parts"]
                .as_array_mut()
                .unwrap()
                .pop();
            assert!(
                std::panic::catch_unwind(|| assert_placement_equivalent(&wrong, &wrong)).is_err()
            );
        }
    }

    // Commit 6's oracle rows hold this comparator.
    #[allow(dead_code)]
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

        /// [format] quiet default accepts zero anchor reads.
        #[test]
        fn quiet_default_accepts_zero_anchor_reads() {
            assert_quiet_restart_zero_bytes(&quiet_result(0));
        }

        /// [format] quiet default rejects anchor reads.
        #[test]
        #[should_panic(expected = "identity anchor I/O unmeasured or outside exact window")]
        fn quiet_default_rejects_anchor_reads() {
            assert_quiet_restart_zero_bytes(&quiet_result(ANCHOR_WINDOW));
        }

        /// [format] quiet anchor window accepts exact count.
        #[test]
        fn quiet_anchor_window_accepts_exact_count() {
            assert_quiet_restart_with_anchor_window(&quiet_result(ANCHOR_WINDOW), ANCHOR_WINDOW);
        }

        /// [format] quiet anchor window rejects short count.
        #[test]
        #[should_panic(expected = "identity anchor I/O unmeasured or outside exact window")]
        fn quiet_anchor_window_rejects_short_count() {
            assert_quiet_restart_with_anchor_window(
                &quiet_result(ANCHOR_WINDOW - 1),
                ANCHOR_WINDOW,
            );
        }

        /// [format] quiet anchor window rejects excess count.
        #[test]
        #[should_panic(expected = "identity anchor I/O unmeasured or outside exact window")]
        fn quiet_anchor_window_rejects_excess_count() {
            assert_quiet_restart_with_anchor_window(
                &quiet_result(ANCHOR_WINDOW + 1),
                ANCHOR_WINDOW,
            );
        }

        /// [format] quiet anchor window rejects body bytes.
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

        /// [format] quiet anchor window rejects other reads.
        #[test]
        #[should_panic(expected = "other I/O unmeasured/nonzero")]
        fn quiet_anchor_window_rejects_other_reads() {
            let mut result = quiet_result(ANCHOR_WINDOW);
            result.io.other_reads = Some(1);
            assert_quiet_restart_with_anchor_window(&result, ANCHOR_WINDOW);
        }

        /// [format] quiet anchor window rejects unmeasured anchors.
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

/// [format] scan clock restores after nested scope and unwind.
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

/// Native cold-store setup shared by transition tests. Scans stop before
/// policy finalization, ACK and save; each driver chooses its settlement.
pub(crate) mod native_cold {
    use crate::snapshots::*;
    use crate::transcript_acquisition::Scope;

    pub(in crate::snapshots) fn parser(
        source: SnapshotSource,
        path: &Path,
        file: std::fs::File,
        apply: fn(&serde_json::Value, &mut SnapshotAccumulator),
    ) -> OwnedJsonlParser {
        OwnedJsonlParser::new(file, path, source, apply, None, None, None).unwrap()
    }
    pub(in crate::snapshots) fn finish_record(
        parser: &mut OwnedJsonlParser,
        scope: &Scope,
        now: u64,
    ) -> (
        crate::snapshots::sampled_jsonl::CachedJsonlReduction,
        crate::transcript_acquisition::Checkpoint,
    ) {
        while !parser.step().unwrap() {}
        let reduction = parser.durable_test_reduction_copy();
        let checkpoint = match parser.certify_without_retention(scope, now).unwrap() {
            crate::snapshots::sampled_jsonl::SideCertificate::Certified { completed, .. } => {
                completed.checkpoint
            }
            _ => panic!("a clean native fixture is certified"),
        };
        (reduction, checkpoint)
    }
}
