//! Class L priority hints only: acknowledged bucket starts, never identities.
use super::*;
use serde::Deserializer;

pub(crate) const MAX_SESSIONS: usize = 64;
// Receiver's per-item bucket bound. Each entry is also intersected with the
// accepted body's actual bucket set, so deletion follows the body's entry.
pub(crate) const MAX_BUCKETS: usize = 5_000;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct AcceptedBuckets(BTreeMap<String, Vec<i64>>);

fn session_key(session: &str) -> String {
    super::super::sha256_hex(&["claude_accepted_identity_buckets:v1", session])
}
pub(super) fn bucket_key(start: &str) -> Option<i64> {
    OffsetDateTime::parse(start, &Rfc3339)
        .ok()
        .map(|at| at.unix_timestamp())
}
impl<'de> Deserialize<'de> for AcceptedBuckets {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        // Losing an L hint must not invalidate neighbouring billing ACKs.
        let value = Value::deserialize(decoder)?;
        Ok(Self(
            value
                .as_object()
                .into_iter()
                .flat_map(|map| map.iter())
                .filter_map(|(session, starts)| {
                    if !hash_is_valid(session) {
                        return None;
                    }
                    let starts = starts.as_array()?;
                    if starts.len() > MAX_BUCKETS {
                        return None;
                    }
                    Some((
                        session.clone(),
                        starts
                            .iter()
                            .map(Value::as_i64)
                            .collect::<Option<BTreeSet<_>>>()?
                            .into_iter()
                            .collect(),
                    ))
                })
                .take(MAX_SESSIONS)
                .collect(),
        ))
    }
}
impl AcceptedBuckets {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn get(&self, session: &str) -> Option<&[i64]> {
        self.0.get(&session_key(session)).map(Vec::as_slice)
    }
    /// Only the stored-body ACK seam calls this. A stripped revision does not
    /// erase remembered proof; restoration still requires today's grouping.
    pub(crate) fn record(&mut self, body: &Value) {
        if body["provenance"]["collector"].as_str() != Some(COLLECTOR) {
            return;
        }
        let Some(session) = body["source_session_id"].as_str() else {
            return;
        };
        let Some(buckets) = body["usage_buckets"].as_array() else {
            return;
        };
        if buckets.len() > MAX_BUCKETS {
            return;
        }
        let key = session_key(session);
        if !self.0.contains_key(&key) && self.0.len() == MAX_SESSIONS {
            // Class L eviction degrades to the counted missing-state path.
            self.0.pop_first();
        }
        let entry = self.0.entry(key).or_default();
        let mut known = std::mem::take(entry).into_iter().collect::<BTreeSet<_>>();
        let mut present = BTreeSet::new();
        for bucket in buckets {
            let Some(start) = bucket["bucket_start"].as_str().and_then(bucket_key) else {
                continue;
            };
            present.insert(start);
            let tagged = bucket["model_usage"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|row| {
                    row["evidence_ref"].as_u64().is_some()
                        || row["identity_parts"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|part| part["evidence_ref"].as_u64().is_some())
                });
            if tagged {
                known.insert(start);
            }
        }
        known.retain(|start| present.contains(start));
        *entry = known.into_iter().collect();
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for AcceptedBuckets {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.0, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn body(tagged: bool) -> Value {
        json!({"source_session_id":"synthetic", "provenance":{"collector":COLLECTOR},
        "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z", "model_usage":[
            if tagged { json!({"evidence_ref":0}) } else { json!({}) }
        ]}]})
    }
    #[test]
    fn record_retains_keys_across_stripped_revisions_and_restart_without_identities() {
        let mut state = AcceptedBuckets::default();
        state.record(&body(true));
        state.record(&body(false));
        let bytes = serde_json::to_vec(&state).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("synthetic"));
        let mut restored: AcceptedBuckets = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.get("synthetic").unwrap().len(), 1);
        let mut deleted = body(false);
        deleted["usage_buckets"] = json!([]);
        restored.record(&deleted);
        assert!(restored.get("synthetic").unwrap().is_empty());
    }
    #[test]
    fn decoder_and_record_are_bounded_and_unknown_is_distinct_from_known_empty() {
        let oversized = json!((0..MAX_BUCKETS + 1).collect::<Vec<_>>());
        let raw = (0..MAX_SESSIONS + 1)
            .map(|i| (format!("{i:064x}"), json!([1, 2, 3])))
            .collect::<serde_json::Map<_, _>>();
        let decoded: AcceptedBuckets = serde_json::from_value(Value::Object(raw)).unwrap();
        assert_eq!(decoded.0.len(), MAX_SESSIONS);
        let decoded: AcceptedBuckets =
            serde_json::from_value(json!({"a".repeat(64):oversized})).unwrap();
        assert!(decoded.is_empty());
        let mut state = AcceptedBuckets::default();
        for i in 0..MAX_SESSIONS + 1 {
            let mut value = body(false);
            value["source_session_id"] = json!(format!("session-{i}"));
            state.record(&value);
        }
        assert_eq!(state.0.len(), MAX_SESSIONS);
        assert!(state.get("never-acknowledged").is_none());
        assert_eq!(
            state.get(&format!("session-{MAX_SESSIONS}")).unwrap().len(),
            0
        );
    }
}

#[cfg(all(test, target_pointer_width = "64"))]
mod heap_tests {
    use super::*;
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    #[test]
    fn maximum_priority_ledger_has_a_three_mib_heap_bound() {
        let state = AcceptedBuckets(
            (0..MAX_SESSIONS)
                .map(|n| (format!("{n:064x}"), (0..MAX_BUCKETS as i64).collect()))
                .collect(),
        );
        let mut counter = Counter::new(3 * 1024 * 1024);
        counter.add(std::mem::size_of_val(&state)).unwrap();
        state.heap_bound(&mut counter).unwrap();
        assert_eq!(counter.bytes, 2_621_320);
        assert_eq!(
            state.0.values().map(Vec::len).sum::<usize>(),
            MAX_SESSIONS * MAX_BUCKETS
        );
    }
}
