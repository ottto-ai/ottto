//! Cache-observation upload state: merging a patch into the accepted rows,
//! preparing one item's patch against its acknowledged predecessor within
//! the server's bounds, and building one session's cache wire.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::snapshots::cache_observations::{self, CacheObservations, OwnedRequest};
use crate::snapshots::SnapshotItem;

/// Refuse a malformed accepted row rather than silently dropping its bytes/row
/// from the cumulative bound. No patch can authorize that implicit deletion.
pub(crate) fn cache_state_from_patch(
    previous: Option<&Value>,
    patch: &CacheObservations,
) -> Option<Value> {
    let mut observations = BTreeMap::<String, cache_observations::Observation>::new();
    // A marked replacement completes from empty, on both sides of the wire.
    if let Some(previous) = previous.filter(|_| !patch.full_replacement) {
        for row in previous.get("observations")?.as_array()? {
            let row =
                serde_json::from_value::<cache_observations::Observation>(row.clone()).ok()?;
            observations.insert(row.event_id.clone(), row);
        }
    }
    for operation in &patch.operations {
        match operation {
            cache_observations::Operation::Upsert { observation } => {
                if observation.status == "retracted" {
                    observations.remove(&observation.event_id);
                } else {
                    observations.insert(observation.event_id.clone(), observation.as_ref().clone());
                }
            }
            cache_observations::Operation::Retract { event_id } => {
                observations.remove(event_id);
            }
        }
    }
    Some(
        json!({"schema_version":1,"observations":observations.into_values().collect::<Vec<_>>(),"coverage":patch.coverage,"omitted_observation_count":patch.omitted_observation_count}),
    )
}
/// A server-echoed completed state (`cache_state_ack:v1`) rebuilt through the
/// patch path: the echo's coverage must pass `validate`, its rows must parse,
/// and the result must stay within the state bounds. A repeated row or a
/// malformed omitted count changes the rebuilt state, so its witness cannot
/// match the server's digest.
pub(crate) fn cache_state_from_echo(echo: &Value) -> Option<Value> {
    let empty = CacheObservations {
        schema_version: u16::try_from(echo.get("schema_version")?.as_u64()?).ok()?,
        operations: Vec::new(),
        coverage: echo.get("coverage")?.as_str()?.into(),
        omitted_observation_count: echo
            .get("omitted_observation_count")
            .and_then(Value::as_u64),
        full_replacement: false,
    };
    let state = cache_state_from_patch(Some(echo), &empty).filter(|_| empty.validate())?;
    cache_state_within_limits(&state).then_some(state)
}
/// Preflight the exact wire and its completion against the ACKed predecessor.
/// Partial coverage never authorizes deletion, including after budget trimming.
pub(crate) fn prepare_cache_observations(item: &mut SnapshotItem, prior: Option<&Value>) {
    let Some(patch) = item.cache_observations.as_ref() else {
        return;
    };
    let desired = cache_state_from_patch(None, patch).expect("no accepted rows to parse");
    let ids = desired["observations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["event_id"].as_str())
        .collect::<BTreeSet<_>>();
    let mut wire = patch.clone();
    if patch.coverage == "complete" {
        // Keep the established complete-patch wire order. The selected Codex
        // patch stays in session order for the partial fallback below.
        wire.operations.sort_by(|a, b| {
            let a = match a {
                cache_observations::Operation::Upsert { observation } => &observation.event_id,
                cache_observations::Operation::Retract { event_id } => event_id,
            };
            let b = match b {
                cache_observations::Operation::Upsert { observation } => &observation.event_id,
                cache_observations::Operation::Retract { event_id } => event_id,
            };
            a.cmp(b)
        });
        // Retract only a correction: a row on a request this read saw that the
        // detector no longer reports. A row on a request it never saw (one
        // adopted from the server's echoed state) is kept, not retracted.
        let seen = item
            .cache_requests
            .iter()
            .map(|request| request.slot.request_ref.as_str())
            .collect::<BTreeSet<_>>();
        for row in prior
            .and_then(|p| p["observations"].as_array())
            .into_iter()
            .flatten()
        {
            if let Some(id) = row["event_id"].as_str() {
                let request = row["affected_request_ref"].as_str();
                if !ids.contains(id) && request.is_some_and(|r| seen.contains(r)) {
                    wire.operations
                        .push(cache_observations::Operation::Retract {
                            event_id: id.into(),
                        });
                }
            }
        }
        if !wire.validate() {
            // Over the server's per-patch bound: send only what it lacks, so
            // the rest of a long session follows on its next upload.
            let held = cache_rows_held(prior);
            wire.operations
                .retain(|operation| !cache_row_held(&held, operation));
        }
        let Some(state) = cache_state_from_patch(prior, &wire) else {
            item.cache_observations = None;
            item.cache_observations_state = None;
            return;
        };
        if wire.validate() && cache_state_within_limits(&state) {
            item.cache_observations_state = Some(state);
            item.cache_observations = Some(wire);
            return;
        }
    }

    // Preserve all accepted evidence on partial/refused corrections. A prior ID
    // outside the selected prefix prevents an exact missing-observation count.
    let prior_is_prefix = prior
        .and_then(|p| p["observations"].as_array())
        .into_iter()
        .flatten()
        .all(|row| row["event_id"].as_str().is_some_and(|id| ids.contains(id)));
    let overflow = if prior_is_prefix {
        if patch.coverage == "complete" {
            Some(0)
        } else {
            patch.omitted_observation_count
        }
    } else {
        None
    };
    wire = patch.clone();
    wire.coverage = "partial".into();
    let held = cache_rows_held(prior);
    wire.operations.retain(|operation| {
        matches!(operation,
        cache_observations::Operation::Upsert { observation } if observation.status != "retracted")
            && !cache_row_held(&held, operation)
    });
    // The earliest rows the server lacks, at most one patch's worth; later
    // rows follow on the next upload.
    wire.operations.truncate(cache_observations::MAX_OPERATIONS);
    loop {
        let Some(mut state) = cache_state_from_patch(prior, &wire) else {
            item.cache_observations = None;
            item.cache_observations_state = None;
            return;
        };
        let present = state["observations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["event_id"].as_str())
            .collect::<BTreeSet<_>>();
        let missing = ids.difference(&present).count() as u64;
        wire.omitted_observation_count = overflow.and_then(|count| count.checked_add(missing));
        state["omitted_observation_count"] = json!(wire.omitted_observation_count);
        if wire.validate() && cache_state_within_limits(&state) {
            item.cache_observations_state = Some(state);
            item.cache_observations = Some(wire);
            return;
        }
        // Removing a shrinking replacement can INCREASE completed bytes. Always
        // recompute the actual merge; do not assume monotonic sizes.
        if wire.operations.pop().is_none() {
            // Withholding preserves accepted evidence, including possibly stale
            // server coverage="complete": no cache metadata reaches the server.
            // The Claude-only reread diagnostics do not count this upload refusal.
            item.cache_observations = None;
            item.cache_observations_state = None;
            return;
        }
    }
}
/// The accepted rows by event id. An unreadable row is left out, so its
/// replacement is sent.
fn cache_rows_held(prior: Option<&Value>) -> BTreeMap<String, cache_observations::Observation> {
    prior
        .and_then(|prior| prior["observations"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|row| {
            serde_json::from_value::<cache_observations::Observation>(row.clone()).ok()
        })
        .map(|row| (row.event_id.clone(), row))
        .collect()
}
/// An upsert of a row the server already holds unchanged.
fn cache_row_held(
    held: &BTreeMap<String, cache_observations::Observation>,
    operation: &cache_observations::Operation,
) -> bool {
    matches!(operation, cache_observations::Operation::Upsert { observation }
        if held.get(&observation.event_id) == Some(observation.as_ref()))
}
pub(in crate::snapshots) fn cache_state_within_limits(state: &Value) -> bool {
    state["observations"].as_array().is_some_and(|rows| {
        rows.len() <= cache_observations::MAX_ROWS
            && rows.iter().all(|row| row["status"] != "retracted")
    }) && crate::canonical_json::canonicalize(state)
        .is_ok_and(|bytes| bytes.len() <= cache_observations::MAX_STATE_BYTES)
}
/// One session's cache wire, shared by every source. A replayed request is
/// one request; a conflicting replay or an unparseable time cannot certify
/// an omitted count, nor can an incomplete request book: those ship
/// `partial` with no rows. Rows stay in session order, so an upload that
/// must trim drops the latest first.
pub(in crate::snapshots) fn cache_wire<'a>(
    session: &str,
    requests: impl IntoIterator<Item = &'a OwnedRequest>,
    complete: bool,
) -> CacheObservations {
    let mut seen = BTreeMap::new();
    let mut unique = Vec::new();
    for request in requests {
        if OffsetDateTime::parse(&request.slot.occurred_at, &Rfc3339).is_err() {
            return CacheObservations::partial(None);
        }
        match seen.get(&request.slot.request_ref) {
            Some(prior) if prior != &request.slot => return CacheObservations::partial(None),
            Some(_) => {}
            None => {
                seen.insert(request.slot.request_ref.clone(), request.slot.clone());
                unique.push(request.clone());
            }
        }
    }
    if !complete {
        return CacheObservations::partial(None);
    }
    CacheObservations {
        schema_version: 1,
        operations: cache_observations::detect_unique(session, &unique)
            .into_iter()
            .map(|observation| cache_observations::Operation::Upsert {
                observation: Box::new(observation),
            })
            .collect(),
        coverage: "complete".into(),
        omitted_observation_count: None,
        full_replacement: false,
    }
}
