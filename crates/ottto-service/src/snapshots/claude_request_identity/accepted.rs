//! Class L hints: bucket starts and non-reversible accepted share fingerprints.
use super::*;
use hmac::{Hmac, Mac};
use serde::{Deserializer, Serializer};
use std::ops::Deref;
use zeroize::Zeroizing;

pub(crate) const MAX_SESSIONS: usize = 16;
pub(crate) const MAX_BUCKETS: usize = 5_000;
const MAX_SHARES: usize = 1_536;

// Runtime keys never serialize and Debug must never expose their bytes.
#[derive(Clone, PartialEq, Eq)]
struct FingerprintKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FingerprintKey([redacted])")
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AcceptedBuckets(BTreeMap<String, AcceptedSession>, Option<FingerprintKey>);
#[cfg(test)]
fn fixture_key() -> FingerprintKey {
    FingerprintKey(Zeroizing::new([0x42; 32]))
}
impl Serialize for AcceptedBuckets {
    fn serialize<S: Serializer>(&self, encoder: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(encoder)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptedSession {
    // Required: unkeyed v1 records have no epoch and decode as unknown.
    key_epoch: [u8; 32],
    #[serde(skip)]
    key: Option<FingerprintKey>,
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
fn digest(key: &FingerprintKey, value: Value) -> [u8; 32] {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.0.as_ref()).expect("HMAC key");
    mac.update(b"ottto:session-attribution:");
    mac.update(&serde_json::to_vec(&value).expect("JSON fingerprint"));
    mac.finalize().into_bytes().into()
}
fn key_epoch(key: &FingerprintKey) -> [u8; 32] {
    digest(
        key,
        json!([
            "claude_accepted_key_epoch:v2",
            crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION
        ]),
    )
}
fn row_hash(key: &FingerprintKey, row: &RowKey) -> [u8; 32] {
    digest(
        key,
        json!([
            "claude_accepted_row:v2",
            row.model,
            row.selector_hash,
            row.reasoning_effort,
            row.billing_fields()
        ]),
    )
}
fn authority_hash(key: &FingerprintKey, authority: &AuthorityKey) -> [u8; 32] {
    digest(
        key,
        json!([
            "claude_accepted_authority:v2",
            authority.login,
            authority.org,
            authority.basis
        ]),
    )
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
fn session_key(key: &FingerprintKey, session: &str) -> String {
    digest(key, json!(["claude_accepted_identity_buckets:v2", session]))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(super) fn bucket_key(start: &str) -> Option<i64> {
    OffsetDateTime::parse(start, &Rfc3339)
        .ok()
        .map(|at| at.unix_timestamp())
}
impl AcceptedSession {
    pub(super) fn authority_hash(&self, authority: &AuthorityKey) -> [u8; 32] {
        authority_hash(self.key.as_ref().expect("bound accepted epoch"), authority)
    }
    pub(super) fn row_shares(&self, bucket: i64, row: &RowKey) -> BTreeSet<Option<[u8; 32]>> {
        let row = row_hash(self.key.as_ref().expect("bound accepted epoch"), row);
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
        let decoded = Self(
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
            None,
        );
        Ok(decoded)
    }
}
impl AcceptedBuckets {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self(BTreeMap::new(), Some(fixture_key()))
    }
    #[cfg(test)]
    pub(crate) fn restore_for_test(bytes: &[u8]) -> Self {
        let mut state: Self = serde_json::from_slice(bytes).unwrap();
        state.bind_key(Some(fixture_key()));
        state
    }
    /// The negotiated attribution key is owned by the existing per-cycle context.
    /// Missing or rotated keys discard hints before any share comparison or ACK.
    pub(crate) fn bind_context(
        &mut self,
        context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) {
        self.bind_key(context.map(|context| FingerprintKey(context.accepted_fingerprint_key())));
    }
    #[cfg(test)]
    pub(crate) fn bind_test_key(&mut self, key: Option<[u8; 32]>) {
        self.bind_key(key.map(|key| FingerprintKey(Zeroizing::new(key))));
    }
    fn bind_key(&mut self, key: Option<FingerprintKey>) {
        let epoch = key.as_ref().map(key_epoch);
        if epoch.is_none() || self.0.values().any(|state| Some(state.key_epoch) != epoch) {
            self.0.clear();
        }
        for state in self.0.values_mut() {
            state.key = key.clone();
        }
        self.1 = key;
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn get(&self, session: &str) -> Option<&AcceptedSession> {
        let key = self.1.as_ref()?;
        self.0
            .get(&session_key(key, session))
            .filter(|state| state.key_epoch == key_epoch(key))
    }
    /// Record only the body actually stored. A stripped ACK preserves prior
    /// fingerprints while the bucket is present; fingerprints never restore tags.
    pub(crate) fn record(&mut self, body: &Value) {
        let Some(fingerprint_key) = self.1.as_ref() else {
            return;
        };
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
        let key = session_key(fingerprint_key, session);
        if !self.0.contains_key(&key) && self.0.len() == MAX_SESSIONS {
            self.0.pop_first();
        }
        let entry = self.0.entry(key).or_insert_with(|| AcceptedSession {
            key_epoch: key_epoch(fingerprint_key),
            key: Some(fingerprint_key.clone()),
            ..Default::default()
        });
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
                let row_hash = row_hash(fingerprint_key, &row_key);
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
                            Some(authority_hash(
                                fingerprint_key,
                                &AuthorityKey {
                                    login: part["account_identifier_hash"]
                                        .as_str()
                                        .map(str::to_owned),
                                    org: evidence["provider_workspace_hash"]
                                        .as_str()
                                        .map(str::to_owned),
                                    basis,
                                },
                            ))
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
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .into_vec();
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
    pub(super) fn body(tagged: bool) -> Value {
        json!({"source_session_id":"synthetic", "provenance":{"collector":COLLECTOR},
        "request_evidence":[{"identity_basis":TELEMETRY_LOGIN}], "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z", "model_usage":[
            if tagged { json!({"model":"claude-synthetic","evidence_ref":0,"account_identifier_hash":"a".repeat(64)}) } else { json!({"model":"claude-synthetic"}) }
        ]}]})
    }
    #[test]
    fn record_retains_keys_across_stripped_revisions_and_restart_without_identities() {
        let mut state = AcceptedBuckets::for_test();
        state.record(&body(true));
        state.record(&body(false));
        let bytes = serde_json::to_vec(&state).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("synthetic"));
        assert!(!String::from_utf8_lossy(&bytes).contains(&"a".repeat(64)));
        let mut restored: AcceptedBuckets = AcceptedBuckets::restore_for_test(&bytes);
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
            .map(|i| {
                (
                    format!("{i:064x}"),
                    json!({"key_epoch":key_epoch(&fixture_key()),"starts":[],"shares":[]}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let decoded: AcceptedBuckets = serde_json::from_value(Value::Object(raw)).unwrap();
        assert_eq!(decoded.0.len(), MAX_SESSIONS);
        let decoded: AcceptedBuckets =
            serde_json::from_value(json!({"a".repeat(64):oversized})).unwrap();
        assert!(decoded.is_empty());
        let mut state = AcceptedBuckets::for_test();
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
                            key_epoch: [0; 32],
                            key: None,
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
            None,
        );
        let mut counter = Counter::new(3 * 1024 * 1024);
        counter.add(std::mem::size_of_val(&state)).unwrap();
        state.heap_bound(&mut counter).unwrap();
        assert!(counter.bytes < 3 * 1024 * 1024);
        assert_eq!(
            counter.bytes,
            2_628_072
                + 17 * 11 * (std::mem::size_of::<AcceptedSession>() - 56)
                + std::mem::size_of::<AcceptedBuckets>()
                - 24
        );
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
            serde_json::from_value(json!({session_key(&fixture_key(), "old"): [1, 2]})).unwrap();
        assert!(state.get("old").is_none());
    }
}

#[cfg(test)]
mod share_bound_tests {
    use super::*;
    #[test]
    fn record_evicts_whole_share_sets_and_counts_state_as_incomplete() {
        let start = OffsetDateTime::parse("2026-09-01T00:00:00Z", &Rfc3339).unwrap();
        let body = json!({"source_session_id":"bounded-shares","provenance":{"collector":COLLECTOR},
            "request_evidence":[{"identity_basis":TELEMETRY_LOGIN}],
            "usage_buckets":(0..MAX_SHARES / 3 + 1).map(|hour| json!({
                "bucket_start":(start+time::Duration::hours(hour as i64)).format(&Rfc3339).unwrap(),
                "model_usage":[{"model":"claude-synthetic","identity_parts":(0..3).map(|key| json!({
                    "evidence_ref":0,"account_identifier_hash":format!("{key:064x}")
                })).collect::<Vec<_>>()}]
            })).collect::<Vec<_>>()});
        let mut state = AcceptedBuckets::for_test();
        state.record(&body);
        let known = state.get("bounded-shares").unwrap();
        assert!(known.incomplete);
        assert_eq!(known.shares.len(), MAX_SHARES);
        assert_eq!(known.shares.capacity(), MAX_SHARES);
        assert_eq!(known.starts.len(), MAX_SHARES / 3);
        assert!(known
            .shares
            .iter()
            .all(|share| share.bucket != start.unix_timestamp()));
        let restored: AcceptedBuckets =
            AcceptedBuckets::restore_for_test(&serde_json::to_vec(&state).unwrap());
        assert_eq!(restored, state);
    }
}

#[cfg(test)]
mod keyed_tests {
    use super::*;
    #[test]
    fn fixed_key_is_deterministic_and_not_plain_sha256_of_identity_json() {
        let key = fixture_key();
        let authority = AuthorityKey {
            login: Some("low-entropy-login".into()),
            org: Some("low-entropy-org".into()),
            basis: TELEMETRY_LOGIN,
        };
        let material = json!([
            "claude_accepted_authority:v2",
            authority.login,
            authority.org,
            authority.basis
        ]);
        let actual = authority_hash(&key, &authority);
        assert_eq!(actual, authority_hash(&key, &authority));
        assert_ne!(
            actual,
            <[u8; 32]>::from(sha2::Sha256::digest(serde_json::to_vec(&material).unwrap()))
        );
        let row = wire_row_key(&json!({"model":"synthetic-model"})).unwrap();
        let material = json!([
            "claude_accepted_row:v2",
            row.model,
            row.selector_hash,
            row.reasoning_effort,
            row.billing_fields()
        ]);
        assert_ne!(
            row_hash(&key, &row),
            <[u8; 32]>::from(sha2::Sha256::digest(serde_json::to_vec(&material).unwrap()))
        );
        let mut first = AcceptedBuckets::for_test();
        first.record(&tests::body(true));
        let mut second = AcceptedBuckets::for_test();
        second.record(&tests::body(true));
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains(&"a".repeat(64)));
        assert!(!encoded.contains("synthetic"));
        assert!(!format!("{first:?}").contains("66, 66"));
        assert_ne!(
            session_key(&key, "synthetic"),
            super::super::super::sha256_hex(&["claude_accepted_identity_buckets:v2", "synthetic"])
        );
    }
    #[test]
    fn rotated_missing_or_changed_version_keys_drop_the_entire_set() {
        let mut state = AcceptedBuckets::for_test();
        state.record(&tests::body(true));
        let bytes = serde_json::to_vec(&state).unwrap();
        for key in [None, Some([0x43; 32])] {
            let mut restored: AcceptedBuckets = serde_json::from_slice(&bytes).unwrap();
            restored.bind_test_key(key);
            assert!(restored.is_empty());
            assert!(restored.get("synthetic").is_none());
            restored.record(&tests::body(true));
            assert_eq!(restored.is_empty(), key.is_none());
        }
        let mut version_changed = serde_json::to_value(&state).unwrap();
        version_changed
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()["key_epoch"] = json!(vec![0; 32]);
        let mut restored: AcceptedBuckets = serde_json::from_value(version_changed).unwrap();
        restored.bind_test_key(Some([0x42; 32]));
        assert!(restored.is_empty());
    }
    #[test]
    fn negotiated_context_binds_the_existing_key_and_restart_requires_rebinding() {
        use base64::Engine as _;
        let home = std::path::Path::new("/nonexistent/e2-accepted-fingerprints");
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]);
        let context = crate::session_attribution::SessionAttributionContext::from_activity_hint(
            SnapshotSource::ClaudeCode,
            home,
            true,
            Some(&encoded),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap();
        let mut state = AcceptedBuckets::default();
        state.record(&tests::body(true));
        assert!(state.is_empty());
        state.bind_context(Some(&context));
        assert_eq!(state.1.as_ref(), Some(&fixture_key()));
        state.record(&tests::body(true));
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut restored: AcceptedBuckets = serde_json::from_slice(&bytes).unwrap();
        assert!(restored.get("synthetic").is_none());
        restored.bind_context(Some(&context));
        assert_eq!(restored, state);
        restored.bind_context(None);
        restored.record(&tests::body(true));
        assert!(restored.is_empty());
    }
    #[test]
    fn round_five_unkeyed_v1_share_state_is_unknown() {
        let key =
            super::super::super::sha256_hex(&["claude_accepted_identity_buckets:v1", "synthetic"]);
        let restored: AcceptedBuckets = serde_json::from_value(json!({key:{
            "starts":[1], "shares":[{"bucket":1,"row":vec![0;32],"authority":vec![1;32]}], "incomplete":false
        }})).unwrap();
        assert!(restored.is_empty());
        assert!(restored.get("synthetic").is_none());
    }
}
