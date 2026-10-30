//! Class L hints: bucket starts and non-reversible accepted share fingerprints.
use super::*;
use serde::Deserializer;
use std::ops::Deref;

pub(crate) const MAX_SESSIONS: usize = 16;
pub(crate) const MAX_BUCKETS: usize = 5_000;
const MAX_SHARES: usize = 1_536;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct AcceptedBuckets(BTreeMap<String, AcceptedSession>);
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptedSession {
    starts: Vec<i64>,
    shares: Vec<AcceptedShare>,
    #[serde(default)]
    pub(super) incomplete: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct AcceptedShare {
    bucket: i64,
    row: [u8; 32],
    authority: Option<[u8; 32]>,
}
impl Deref for AcceptedSession {
    type Target = [i64];
    fn deref(&self) -> &Self::Target {
        &self.starts
    }
}
fn digest(value: Value) -> [u8; 32] {
    sha2::Sha256::digest(serde_json::to_vec(&value).expect("JSON fingerprint")).into()
}
fn row_hash(row: &RowKey) -> [u8; 32] {
    digest(json!([
        "claude_accepted_row:v1",
        row.model,
        row.selector_hash,
        row.reasoning_effort,
        row.billing_fields()
    ]))
}
pub(super) fn authority_hash(key: &AuthorityKey) -> [u8; 32] {
    digest(json!([
        "claude_accepted_authority:v1",
        key.login,
        key.org,
        key.basis
    ]))
}
fn wire_row_key(row: &Value) -> Option<RowKey> {
    let text = |name: &str| row[name].as_str().map(str::to_owned);
    let context = match row["selector_context"].as_object() {
        Some(context) => context
            .iter()
            .map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
            .collect::<Option<BTreeMap<_, _>>>()?,
        None => BTreeMap::new(),
    };
    Some(RowKey {
        model: text("model")?,
        selector_hash: super::super::selector_hash(&context),
        reasoning_effort: text("reasoning_effort"),
        auth_mode: text("auth_mode"),
        billing_channel: text("billing_channel"),
        billing_provider: text("billing_provider"),
        gateway_provider: text("gateway_provider"),
        model_provider: text("model_provider"),
        subscription_product: text("subscription_product"),
    })
}
fn basis_token(basis: &str) -> Option<&'static str> {
    match basis {
        TELEMETRY => Some(TELEMETRY),
        TELEMETRY_LOGIN => Some(TELEMETRY_LOGIN),
        TRANSCRIPT_SOLE_LOGIN => Some(TRANSCRIPT_SOLE_LOGIN),
        TRANSCRIPT_ORG => Some(TRANSCRIPT_ORG),
        _ => None,
    }
}
fn session_key(session: &str) -> String {
    super::super::sha256_hex(&["claude_accepted_identity_buckets:v1", session])
}
pub(super) fn bucket_key(start: &str) -> Option<i64> {
    OffsetDateTime::parse(start, &Rfc3339)
        .ok()
        .map(|at| at.unix_timestamp())
}
impl AcceptedSession {
    pub(super) fn row_shares(&self, bucket: i64, row: &RowKey) -> BTreeSet<Option<[u8; 32]>> {
        let row = row_hash(row);
        let first = self
            .shares
            .partition_point(|share| (share.bucket, share.row) < (bucket, row));
        self.shares[first..]
            .iter()
            .take_while(|share| (share.bucket, share.row) == (bucket, row))
            .map(|share| share.authority)
            .collect()
    }
}
impl<'de> Deserialize<'de> for AcceptedBuckets {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        // Invalid, old timestamp-only, or oversized L hints become unknown;
        // they must not invalidate neighbouring billing ACKs or invent proof.
        let value = Value::deserialize(decoder)?;
        Ok(Self(
            value
                .as_object()
                .into_iter()
                .flat_map(|map| map.iter())
                .filter_map(|(session, value)| {
                    if !hash_is_valid(session) {
                        return None;
                    }
                    let mut state: AcceptedSession = serde_json::from_value(value.clone()).ok()?;
                    if state.starts.len() > MAX_BUCKETS || state.shares.len() > MAX_SHARES {
                        return None;
                    }
                    state.starts.sort_unstable();
                    state.starts.dedup();
                    state.shares.sort_unstable();
                    state.shares.dedup();
                    if state
                        .shares
                        .iter()
                        .any(|share| state.starts.binary_search(&share.bucket).is_err())
                    {
                        return None;
                    }
                    // Bound retained capacities too, not only logical lengths.
                    state.starts = state.starts.into_boxed_slice().into_vec();
                    state.shares = state.shares.into_boxed_slice().into_vec();
                    Some((session.clone(), state))
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
    pub(crate) fn get(&self, session: &str) -> Option<&AcceptedSession> {
        self.0.get(&session_key(session))
    }
    /// Record only the body actually stored. A stripped ACK preserves prior
    /// fingerprints while the bucket is present; fingerprints never restore tags.
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
            self.0.pop_first();
        }
        let entry = self.0.entry(key).or_default();
        let mut shares = std::mem::take(&mut entry.shares)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut present = BTreeSet::new();
        for bucket in buckets {
            let Some(start) = bucket["bucket_start"].as_str().and_then(bucket_key) else {
                continue;
            };
            present.insert(start);
            for row in bucket["model_usage"].as_array().into_iter().flatten() {
                let Some(row_key) = wire_row_key(row) else {
                    continue;
                };
                let row_hash = row_hash(&row_key);
                // Freeze a row's first accepted tagged share set. A refused
                // later ACK must not bless its new untagged presence or key.
                if shares
                    .iter()
                    .any(|share| share.bucket == start && share.row == row_hash)
                {
                    continue;
                }
                let parts = row["identity_parts"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(std::slice::from_ref(row));
                let mut row_shares = BTreeSet::new();
                for part in parts {
                    let authority = match part["evidence_ref"]
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                    {
                        None => None,
                        Some(reference) => {
                            let evidence = &body["request_evidence"][reference];
                            let Some(basis) =
                                evidence["identity_basis"].as_str().and_then(basis_token)
                            else {
                                continue;
                            };
                            Some(authority_hash(&AuthorityKey {
                                login: part["account_identifier_hash"].as_str().map(str::to_owned),
                                org: evidence["provider_workspace_hash"]
                                    .as_str()
                                    .map(str::to_owned),
                                basis,
                            }))
                        }
                    };
                    row_shares.insert(AcceptedShare {
                        bucket: start,
                        row: row_hash,
                        authority,
                    });
                }
                if row_shares.iter().any(|share| share.authority.is_some()) {
                    shares.extend(row_shares);
                }
            }
        }
        shares.retain(|share| present.contains(&share.bucket));
        // Evict whole buckets, never a partial share set masquerading as a
        // complete accepted fingerprint. Loss takes the counted unknown path.
        while shares.len() > MAX_SHARES {
            let oldest = shares.first().expect("nonempty").bucket;
            shares.retain(|share| share.bucket != oldest);
            entry.incomplete = true;
        }
        entry.starts = shares
            .iter()
            .map(|share| share.bucket)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        entry.shares = shares
            .into_iter()
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .into_vec();
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for AcceptedSession {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(
            self.starts
                .capacity()
                .checked_mul(std::mem::size_of::<i64>())?,
        )?;
        c.add(
            self.shares
                .capacity()
                .checked_mul(std::mem::size_of::<AcceptedShare>())?,
        )
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
        "request_evidence":[{"identity_basis":TELEMETRY_LOGIN}], "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z", "model_usage":[
            if tagged { json!({"model":"claude-synthetic","evidence_ref":0}) } else { json!({"model":"claude-synthetic"}) }
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
            .map(|i| (format!("{i:064x}"), json!({"starts":[],"shares":[]})))
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
                .map(|n| {
                    (
                        format!("{n:064x}"),
                        AcceptedSession {
                            starts: (0..MAX_BUCKETS as i64).collect(),
                            shares: vec![
                                AcceptedShare {
                                    bucket: 1,
                                    row: [0; 32],
                                    authority: Some([0; 32])
                                };
                                MAX_SHARES
                            ],
                            incomplete: false,
                        },
                    )
                })
                .collect(),
        );
        let mut counter = Counter::new(3 * 1024 * 1024);
        counter.add(std::mem::size_of_val(&state)).unwrap();
        state.heap_bound(&mut counter).unwrap();
        assert!(counter.bytes < 3 * 1024 * 1024);
        eprintln!(
            "accepted-share requested-layout maximum={} bytes",
            counter.bytes
        );
        assert_eq!(
            state.0.values().map(|state| state.len()).sum::<usize>(),
            MAX_SESSIONS * MAX_BUCKETS
        );
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    #[test]
    fn timestamp_only_decoder_state_is_unknown_without_share_fingerprints() {
        let state: AcceptedBuckets =
            serde_json::from_value(json!({session_key("old"): [1, 2]})).unwrap();
        assert!(state.get("old").is_none());
    }
}
