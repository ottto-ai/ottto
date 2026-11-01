//! Class L hints: bucket starts and non-reversible accepted share fingerprints,
//! plus option (ii)'s witnessed proved rows and bounded class H marker grains.
use super::*;
use hmac::{Hmac, Mac};
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use std::ops::Deref;
use zeroize::Zeroizing;

pub(crate) const MAX_SESSIONS: usize = 16;
pub(crate) const MAX_BUCKETS: usize = 5_000;
const MAX_SHARES: usize = 1_536;
/// Receiver's dense identity-parts bound: serialized item bytes / 320.
/// Keep the released ledger limit when the receiver has not raised the cap.
pub(super) const fn max_shares(item_cap: usize) -> usize {
    if item_cap > MAX_ITEM_BYTES {
        item_cap / 320
    } else {
        MAX_SHARES
    }
}
pub(crate) const MAX_PROVED_ROWS: usize = 1_024;
/// Stated design maximum of settled-history segment entries (heap bound). Above it only an alarm counts: segment entries are never evicted
/// by count or recency, only with their session's retirement.
pub(crate) const SEGMENT_DESIGN_MAX: usize = 64;
/// Tombstone for a proof superseded before upload: a keyed digest is never zero.
const REPLACED_PROOF: [u8; 16] = [0; 16];
/// Definite "never accepted" tombstone for proof a copied marker lent
/// (SOURCE 2026-10-31, #944 xPR F5): never a marker, refusal or replacement.
const INVALIDATED_PROOF: [u8; 16] = [0xff; 16];
/// Pending `retained_proof_missing` buckets feed one diagnostic only.
const MAX_PENDING_MISSING: usize = 64;

// Runtime keys never serialize and Debug must never expose their bytes.
#[derive(Clone, PartialEq, Eq)]
struct FingerprintKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FingerprintKey([redacted])")
    }
}
/// Third field: epoch changed this pass; fourth: per-cycle retained
/// capability; fifth: runtime receiver item cap; sixth: the sibling
/// settled-history segment ledger, which has no session cap and no recency
/// eviction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AcceptedBuckets(
    BTreeMap<String, AcceptedSession>,
    Option<FingerprintKey>,
    bool,
    bool,
    usize,
    bool,
);
/// Why a tagging attempt had no complete accepted state (local diagnostics).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum UnknownCause {
    /// No usable attribution key (or no ledger): share protection is off.
    #[default]
    NoKey,
    /// Hints were discarded because the key epoch changed this pass.
    EpochChanged,
    /// No hints for this session: never stored-body ACKed, evicted or invalid.
    UntrackedSession,
    /// Hints exist but whole buckets were evicted at the share limit.
    Incomplete,
}
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
    #[serde(with = "digest_hex")]
    key_epoch: [u8; 32],
    #[serde(skip)]
    key: Option<FingerprintKey>,
    #[serde(default)]
    last_ack: u64,
    starts: Vec<i64>,
    shares: Vec<AcceptedShare>,
    #[serde(default)]
    pub(super) incomplete: bool,
    /// Option (ii): rows whose positive tags a witnessed stored-body ACK
    /// covered, with the keyed digest of that proof; the latest proof wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "proved_hex")]
    proved: Vec<ProvedRow>,
    /// Buckets the server listed in `retained_proof_missing`, until a
    /// witnessed body re-proves them. Local diagnostics only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    missing: Vec<i64>,
    /// Segment entries only: the keyed digest of their live session, so the
    /// live body's cut retires them. Live entries never carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    of: Option<String>,
    /// Segment entries only: the fingerprint of the ACKed segment body, so a
    /// complete census that no longer references the session retires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
}
/// Truncated keyed digests: the (bucket, row) grain and its exact proof.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProvedRow {
    bucket: i64,
    row: [u8; 16],
    proof: [u8; 16],
    // Class H: ACK-bound grain only, bounded and erased with this session.
    account: Option<[u8; 32]>,
}
// Class H must remain private even through derived Debug on containing state.
impl std::fmt::Debug for ProvedRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvedRow")
            .field("bucket", &self.bucket)
            .field("row", &self.row)
            .field("proof", &self.proof)
            .field("account", &"[redacted]")
            .finish()
    }
}
/// Versioned base64 of fixed 73-byte records: bucket, row, proof, optional
/// ACKed account hash. Old hex hints have no grain provenance and fail closed.
mod proved_hex {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    const RECORD: usize = 73;
    pub(super) fn serialize<S: Serializer>(
        rows: &[ProvedRow],
        encoder: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::with_capacity(rows.len() * RECORD);
        for row in rows {
            bytes.extend_from_slice(&row.bucket.to_be_bytes());
            bytes.extend_from_slice(&row.row);
            bytes.extend_from_slice(&row.proof);
            bytes.push(u8::from(row.account.is_some()));
            bytes.extend_from_slice(&row.account.unwrap_or([0; 32]));
        }
        encoder.serialize_str(&format!("v2:{}", STANDARD.encode(bytes)))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        decoder: D,
    ) -> Result<Vec<ProvedRow>, D::Error> {
        let encoded = String::deserialize(decoder)?;
        let invalid = || serde::de::Error::custom("invalid proved rows");
        if encoded.len() > 3 + (MAX_PROVED_ROWS * RECORD).div_ceil(3) * 4 {
            return Err(invalid());
        }
        let bytes = STANDARD
            .decode(encoded.strip_prefix("v2:").ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        if bytes.len() % RECORD != 0 {
            return Err(invalid());
        }
        bytes
            .chunks_exact(RECORD)
            .map(|record| {
                let account = match record[40] {
                    0 if record[41..].iter().all(|byte| *byte == 0) => None,
                    1 => Some(record[41..].try_into().expect("32 bytes")),
                    _ => return Err(invalid()),
                };
                Ok(ProvedRow {
                    bucket: i64::from_be_bytes(record[..8].try_into().expect("8 bytes")),
                    row: record[8..24].try_into().expect("16 bytes"),
                    proof: record[24..40].try_into().expect("16 bytes"),
                    account,
                })
            })
            .collect()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct AcceptedShare {
    bucket: i64,
    #[serde(with = "digest_hex")]
    row: [u8; 32],
    #[serde(with = "optional_digest_hex")]
    authority: Option<[u8; 32]>,
}
mod digest_hex {
    use super::*;
    pub(super) fn encode(value: &[u8; 32]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    pub(super) fn decode<E: serde::de::Error>(value: &str) -> Result<[u8; 32], E> {
        if !hash_is_valid(value) {
            return Err(E::custom("invalid fingerprint"));
        }
        let mut result = [0; 32];
        for (byte, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let digit = |n: u8| if n <= b'9' { n - b'0' } else { n - b'a' + 10 };
            *byte = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        Ok(result)
    }
    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 32],
        encoder: S,
    ) -> Result<S::Ok, S::Error> {
        encoder.serialize_str(&encode(value))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(decoder: D) -> Result<[u8; 32], D::Error> {
        decode(&String::deserialize(decoder)?)
    }
}
mod optional_digest_hex {
    use super::*;
    pub(super) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        encoder: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_ref().map(digest_hex::encode).serialize(encoder)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        decoder: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(decoder)?
            .as_deref()
            .map(digest_hex::decode)
            .transpose()
    }
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
        // The daemon's RowKey partition (`row_key_with_selector_hash`): a
        // marked copy and its unmarked own twin are different rows.
        selector_hash: super::super::copy_unproven_selector_hash(
            row["copy_unproven"] == json!(true),
            super::super::selector_hash(&context),
        ),
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
fn truncated(digest: [u8; 32]) -> [u8; 16] {
    digest[..16].try_into().expect("16-byte prefix")
}
fn proved_row_hash(key: &FingerprintKey, row: &RowKey) -> [u8; 16] {
    truncated(row_hash(key, row))
}
/// Keyed digest of one wire row's identity shares: each share's authority
/// and exact eight counts and five costs. `None` without a positive tag.
fn row_proof(key: &FingerprintKey, row: &Value, evidence: &Value) -> Option<[u8; 16]> {
    const COUNTS: [&str; 8] = [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
        "reasoning_output_tokens",
        "unattributed_total_tokens",
        "request_count",
    ];
    const COSTS: [&str; 5] = [
        "cost_usd",
        "input_cost_usd",
        "output_cost_usd",
        "cache_read_cost_usd",
        "cache_creation_cost_usd",
    ];
    if row.get("identity_retained").is_some() {
        return None;
    }
    let parts = row["identity_parts"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(std::slice::from_ref(row));
    let mut shares = Vec::with_capacity(parts.len());
    for part in parts {
        let authority = match part.get("evidence_ref") {
            None => None,
            Some(reference) => {
                let entry = evidence.get(usize::try_from(reference.as_u64()?).ok()?)?;
                Some(authority_hash(
                    key,
                    &AuthorityKey {
                        login: part["account_identifier_hash"].as_str().map(str::to_owned),
                        org: entry["provider_workspace_hash"].as_str().map(str::to_owned),
                        basis: entry["identity_basis"].as_str().and_then(basis_token)?,
                    },
                ))
            }
        };
        let counts = COUNTS.map(|name| part[name].as_u64().unwrap_or(0));
        let costs = COSTS.map(|name| part[name].as_str().map(str::to_owned));
        shares.push((authority, counts, costs));
    }
    if shares.iter().all(|(authority, _, _)| authority.is_none()) {
        return None;
    }
    shares.sort();
    Some(truncated(digest(
        key,
        json!(["claude_retained_row_proof:v1", shares]),
    )))
}
pub(super) fn bucket_key(start: &str) -> Option<i64> {
    OffsetDateTime::parse(start, &Rfc3339)
        .ok()
        .map(|at| at.unix_timestamp())
}
impl AcceptedSession {
    /// Predict exactly the share set an ACK would retain, without changing proof.
    fn shares_after(
        &self,
        body: &Value,
        shares: impl Iterator<Item = AcceptedShare>,
    ) -> BTreeSet<AcceptedShare> {
        let fingerprint_key = self.bound_key();
        let mut shares = shares.collect::<BTreeSet<_>>();
        let mut present = BTreeSet::new();
        for bucket in body["usage_buckets"].as_array().into_iter().flatten() {
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
        shares
    }
    pub(super) fn exceeds_share_bound(
        &self,
        item: &SnapshotItem,
        item_cap: usize,
        new_shares: usize,
    ) -> bool {
        // The union cannot exceed prior + new shares; avoid building a wire
        // Value on the ordinary path well below the negotiated bound.
        self.shares.len().saturating_add(new_shares) > max_shares(item_cap)
            && serde_json::to_value(item).map_or(true, |body| {
                self.shares_after(&body, self.shares.iter().cloned()).len() > max_shares(item_cap)
            })
    }
    pub(super) fn authority_hash(&self, authority: &AuthorityKey) -> [u8; 32] {
        authority_hash(self.key.as_ref().expect("bound accepted epoch"), authority)
    }
    /// Frozen tagged rows of a present bucket that no current row key matches,
    /// e.g. usage moved to a new key by late effort or billing resolution.
    pub(super) fn vanished_rows<'r>(
        &self,
        bucket: i64,
        current: impl Iterator<Item = &'r RowKey>,
    ) -> u64 {
        let key = self.key.as_ref().expect("bound accepted epoch");
        let current = current
            .map(|row| row_hash(key, row))
            .collect::<BTreeSet<_>>();
        let first = self.shares.partition_point(|share| share.bucket < bucket);
        self.shares[first..]
            .iter()
            .take_while(|share| share.bucket == bucket)
            .map(|share| share.row)
            .filter(|row| !current.contains(row))
            .collect::<BTreeSet<_>>()
            .len() as u64
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
    fn bound_key(&self) -> &FingerprintKey {
        self.key.as_ref().expect("bound accepted epoch")
    }
    /// The keyed proof a witnessed stored body last carried for this row.
    pub(super) fn proved_row(&self, bucket: i64, row: &RowKey) -> Option<[u8; 16]> {
        let row = proved_row_hash(self.bound_key(), row);
        self.proved
            .binary_search_by(|entry| (entry.bucket, entry.row).cmp(&(bucket, row)))
            .ok()
            .map(|index| self.proved[index].proof)
            .filter(|proof| *proof != REPLACED_PROOF && *proof != INVALIDATED_PROOF)
    }
    /// The row holds the copy-derived `INVALIDATED_PROOF` tombstone: no
    /// later witnessed proof replaced it (X-B1 `copy_invalidated`).
    pub(super) fn copy_invalidated(&self, bucket: i64, row: &RowKey) -> bool {
        let row = proved_row_hash(self.bound_key(), row);
        self.proved
            .binary_search_by_key(&(bucket, row), |entry| (entry.bucket, entry.row))
            .is_ok_and(|index| self.proved[index].proof == INVALIDATED_PROOF)
    }
    /// A replacement's reply never settled, so the server may hold either
    /// proof. Kept here because the share hints are evicted independently.
    pub(super) fn replacement_unsettled(&self, bucket: i64, row: &RowKey) -> bool {
        let row = proved_row_hash(self.bound_key(), row);
        self.proved
            .binary_search_by_key(&(bucket, row), |entry| (entry.bucket, entry.row))
            .is_ok_and(|index| self.proved[index].proof == REPLACED_PROOF)
    }
    /// ACKed row hash, for grain only; never an identity authority.
    pub(super) fn proved_account(&self, bucket: i64, row: &RowKey) -> Option<String> {
        let row = proved_row_hash(self.bound_key(), row);
        self.proved
            .binary_search_by_key(&(bucket, row), |entry| (entry.bucket, entry.row))
            .ok()
            .and_then(|index| self.proved[index].account.as_ref().map(digest_hex::encode))
    }
    /// Today's proof digest for a row in its fresh-tag wire form.
    pub(super) fn row_proof(&self, row: &Value, evidence: &Value) -> Option<[u8; 16]> {
        row_proof(self.bound_key(), row, evidence)
    }
    pub(super) fn proof_missing(&self, bucket: i64) -> bool {
        self.missing.binary_search(&bucket).is_ok()
    }
    /// This ledger with `rows` invalidated, for the pass that decides them.
    pub(super) fn invalidated(&self, rows: &[(i64, RowKey)]) -> Self {
        let mut state = self.clone();
        state.invalidate(rows);
        state
    }
    /// Copy-derived rows become a definite "never accepted" record: their
    /// frozen shares go while the bucket stays accepted (the row reads as
    /// ACKed untagged), and a proved row becomes the `INVALIDATED_PROOF`
    /// tombstone, pruned with its bucket. Returns the rows changed.
    fn invalidate(&mut self, rows: &[(i64, RowKey)]) -> u64 {
        let key = self.bound_key().clone();
        let mut changed = 0;
        for (bucket, row) in rows {
            let shared = row_hash(&key, row);
            let before = self.shares.len();
            self.shares
                .retain(|share| (share.bucket, share.row) != (*bucket, shared));
            let mut hit = self.shares.len() != before;
            let proved = proved_row_hash(&key, row);
            if let Ok(at) = self
                .proved
                .binary_search_by_key(&(*bucket, proved), |entry| (entry.bucket, entry.row))
            {
                let held = &mut self.proved[at];
                hit |= held.proof != INVALIDATED_PROOF;
                held.proof = INVALIDATED_PROOF;
                held.account = None;
            }
            changed += u64::from(hit);
        }
        changed
    }
}
impl<'de> Deserialize<'de> for AcceptedBuckets {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_any(Hints { segments: false })
    }
}
/// The sibling `accepted_identity_segments` field: every valid entry decodes,
/// with no session cap. An older daemon ignores the field.
pub(crate) fn decode_segments<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<AcceptedBuckets, D::Error> {
    decoder.deserialize_any(Hints { segments: true })
}
struct Hints {
    segments: bool,
}
impl<'de> Visitor<'de> for Hints {
    type Value = AcceptedBuckets;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("optional accepted identity hints")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut states = BTreeMap::new();
        while let Some(session) = map.next_key::<String>()? {
            if !hash_is_valid(&session) || (!self.segments && states.len() == MAX_SESSIONS) {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            // At most one session Value tree, consumed without cloning.
            // Malformed/old hints never invalidate neighbouring ordinary ACKs.
            let value = map.next_value::<Value>()?;
            let Ok(mut state) = serde_json::from_value::<AcceptedSession>(value) else {
                continue;
            };
            if state.starts.len() > MAX_BUCKETS
                || state.shares.len() > max_shares(MAX_ADVERTISED_ITEM_BYTES)
                || state.proved.len() > MAX_PROVED_ROWS
                || state.missing.len() > MAX_PENDING_MISSING
            {
                continue;
            }
            state.proved.sort_unstable();
            state.proved.dedup_by_key(|entry| (entry.bucket, entry.row));
            state.missing.sort_unstable();
            state.missing.dedup();
            state.starts.sort_unstable();
            state.starts.dedup();
            state.shares.sort_unstable();
            state.shares.dedup();
            if state
                .shares
                .iter()
                .any(|share| state.starts.binary_search(&share.bucket).is_err())
            {
                continue;
            }
            state.starts = state.starts.into_boxed_slice().into_vec();
            state.shares = state.shares.into_boxed_slice().into_vec();
            state.proved = state.proved.into_boxed_slice().into_vec();
            state.missing = state.missing.into_boxed_slice().into_vec();
            states.insert(session, state);
        }
        Ok(AcceptedBuckets(
            states,
            None,
            false,
            false,
            0,
            self.segments,
        ))
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        self.visit_unit()
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(AcceptedBuckets(
            BTreeMap::new(),
            None,
            false,
            false,
            0,
            self.segments,
        ))
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        self.visit_unit()
    }
}
impl AcceptedBuckets {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self(BTreeMap::new(), Some(fixture_key()), false, false, 0, false)
    }
    #[cfg(test)]
    pub(crate) fn segments_for_test() -> Self {
        Self(BTreeMap::new(), Some(fixture_key()), false, false, 0, true)
    }
    /// An empty sibling segment ledger.
    pub(crate) fn segments() -> Self {
        Self(BTreeMap::new(), None, false, false, 0, true)
    }
    #[cfg(test)]
    pub(crate) fn maximum_for_test() -> Self {
        let key = fixture_key();
        Self(
            (0..MAX_SESSIONS)
                .map(|session| {
                    let starts = (0..MAX_BUCKETS)
                        .map(|n| i64::MIN + n as i64)
                        .collect::<Vec<_>>();
                    let shares = (0..MAX_SHARES)
                        .map(|n| {
                            let mut row = [255; 32];
                            row[..8].copy_from_slice(&(n as u64).to_be_bytes());
                            AcceptedShare {
                                bucket: starts[n],
                                row,
                                authority: Some([255; 32]),
                            }
                        })
                        .collect();
                    (
                        session_key(&key, &format!("max-{session}")),
                        AcceptedSession {
                            key_epoch: key_epoch(&key),
                            key: Some(key.clone()),
                            last_ack: u64::MAX,
                            proved: (0..MAX_PROVED_ROWS)
                                .map(|n| ProvedRow {
                                    bucket: starts[n],
                                    row: [255; 16],
                                    proof: [255; 16],
                                    account: Some([255; 32]),
                                })
                                .collect(),
                            missing: starts[..MAX_PENDING_MISSING].to_vec(),
                            starts,
                            shares,
                            incomplete: true,
                            of: None,
                            fingerprint: None,
                        },
                    )
                })
                .collect(),
            Some(key),
            false,
            false,
            0,
            false,
        )
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
        let rotated = self.0.values().any(|state| Some(state.key_epoch) != epoch);
        if epoch.is_none() || rotated {
            self.0.clear();
        }
        self.2 = epoch.is_some() && rotated;
        for state in self.0.values_mut() {
            state.key = key.clone();
        }
        self.1 = key;
    }
    /// A copy reread from disk has no key, and may still hold hints this
    /// cycle's bind discarded. Rebind it like the live ledger before comparing.
    pub(crate) fn adopt_runtime_from(&mut self, live: &Self) {
        self.bind_key(live.1.clone());
        self.2 = live.2;
        self.3 = live.3;
        self.4 = live.4;
    }
    /// Runtime-only receiver cap; never serialized as accepted proof.
    pub(crate) fn set_item_cap(&mut self, item_cap: usize) {
        self.4 = item_cap;
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Option (ii) activation for this cycle: only the server's exact
    /// capability token turns on `identity_retained` rows and recent order.
    pub(crate) fn set_retained_enabled(&mut self, enabled: bool) {
        self.3 = enabled;
    }
    /// Why `get(session)` found no state; meaningful only when it returned `None`.
    pub(crate) fn miss_cause(&self) -> UnknownCause {
        match (&self.1, self.2) {
            (None, _) => UnknownCause::NoKey,
            (Some(_), true) => UnknownCause::EpochChanged,
            (Some(_), false) => UnknownCause::UntrackedSession,
        }
    }
    pub(crate) fn retained_enabled(&self) -> bool {
        self.3
    }
    #[cfg(test)]
    pub(crate) fn forget_share_hints_for_test(&mut self, session: &str) {
        let entry = self.session_mut(session).expect("session");
        entry.shares = Vec::new();
    }
    #[cfg(test)]
    pub(crate) fn proved_rows_for_test(&self, session: &str) -> Option<(usize, usize)> {
        self.get(session).map(|state| {
            let live = state
                .proved
                .iter()
                .filter(|row| row.proof != REPLACED_PROOF && row.proof != INVALIDATED_PROOF);
            (live.count(), state.missing.len())
        })
    }
    pub(crate) fn has_retained(&self) -> bool {
        self.0
            .values()
            .any(|state| !state.proved.is_empty() || !state.missing.is_empty())
    }
    /// A destination namespace or historical replay generation change: the
    /// server's retained proof is not known for the new scope.
    pub(crate) fn clear_retained(&mut self) {
        if !self.has_retained() {
            return;
        }
        for state in self.0.values_mut() {
            state.proved = Vec::new();
            state.missing = Vec::new();
        }
        Self::count_retained_cleared();
    }
    pub(crate) fn count_retained_cleared_if_any(&self) {
        if self.has_retained() {
            Self::count_retained_cleared();
        }
    }
    fn count_retained_cleared() {
        super::budget::record(&super::budget::Counts {
            retained_set_cleared: 1,
            ..Default::default()
        });
    }
    /// Tombstone the copy-derived rows an identity pass treated as never
    /// accepted (`AcceptedSession::invalidate`), counted once per row.
    /// Returns whether the ledger changed; the caller persists before upload.
    pub(crate) fn invalidate_copy_derived(&mut self, rows: &[super::CopyInvalidation]) -> bool {
        let mut invalidated = 0;
        for row in rows {
            if let Some(state) = self.session_mut(&row.session) {
                invalidated += state.invalidate(&[(row.bucket, row.row.clone())]);
            }
        }
        if invalidated > 0 {
            super::budget::record(&super::budget::Counts {
                copy_derived_proof_invalidated: invalidated,
                ..Default::default()
            });
        }
        invalidated > 0
    }
    fn session_mut(&mut self, session: &str) -> Option<&mut AcceptedSession> {
        let key = self.1.as_ref()?;
        let epoch = key_epoch(key);
        self.0
            .get_mut(&session_key(key, session))
            .filter(|state| state.key_epoch == epoch)
    }
    /// The session's entry, refreshed as the last ACK; a full ledger evicts
    /// its least recently ACKed session (#909 LRU).
    fn session_entry(&mut self, session: &str, report: bool) -> Option<&mut AcceptedSession> {
        let fingerprint_key = self.1.as_ref()?;
        let key = session_key(fingerprint_key, session);
        let last_ack = self
            .0
            .values()
            .map(|state| state.last_ack)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        if self.5 {
            // Segment entries leave only with their session's cut (`retire`).
            if !self.0.contains_key(&key) && self.0.len() >= SEGMENT_DESIGN_MAX && report {
                super::budget::record(&super::budget::Counts {
                    accepted_segments_over_design: 1,
                    ..Default::default()
                });
            }
        } else if !self.0.contains_key(&key) && self.0.len() == MAX_SESSIONS {
            let oldest = self
                .0
                .iter()
                .min_by_key(|(key, state)| (state.last_ack, *key))
                .map(|(key, _)| key.clone())
                .expect("full ledger");
            self.0.remove(&oldest);
            if report {
                super::budget::record(&super::budget::Counts {
                    accepted_state_evicted: 1,
                    ..Default::default()
                });
            }
        }
        let entry = self.0.entry(key).or_insert_with(|| AcceptedSession {
            key_epoch: key_epoch(fingerprint_key),
            key: Some(fingerprint_key.clone()),
            ..Default::default()
        });
        entry.last_ack = last_ack;
        Some(entry)
    }
    /// Option (ii) settlement for one stored-body entity ACK. A row enters
    /// only when the ACK carries the exact local body witness and the row had
    /// a positive tag; later positive proof replaces it. Marker and untagged
    /// rows keep the server-held proof. `retained_proof_missing` buckets lose
    /// their marked rows, so a later revision re-tags them if proof remains.
    /// Before an upload: a row this body freshly tags with a different proof
    /// may replace the server's retained proof even if the ACK is lost, so the
    /// superseded entry becomes a tombstone first; a later ACK replaces it.
    /// Returns whether anything changed; the caller persists before the
    /// request. Independent of the capability.
    pub(crate) fn invalidate_replaced(&mut self, body: &Value) -> bool {
        if body["provenance"]["collector"].as_str() != Some(COLLECTOR) {
            return false;
        }
        let Some(session) = body["source_session_id"].as_str() else {
            return false;
        };
        let Some(entry) = self.session_mut(session) else {
            return false;
        };
        if entry.proved.is_empty() {
            return false;
        }
        let key = entry.bound_key().clone();
        let mut replaced = BTreeSet::new();
        for bucket in body["usage_buckets"].as_array().into_iter().flatten() {
            let Some(start) = bucket["bucket_start"].as_str().and_then(bucket_key) else {
                continue;
            };
            for row in bucket["model_usage"].as_array().into_iter().flatten() {
                let (Some(row_key), Some(proof)) = (
                    wire_row_key(row),
                    row_proof(&key, row, &body["request_evidence"]),
                ) else {
                    continue;
                };
                let row_hash = proved_row_hash(&key, &row_key);
                if entry.proved.iter().any(|held| {
                    held.bucket == start
                        && held.row == row_hash
                        && held.proof != proof
                        && held.proof != REPLACED_PROOF
                        && held.proof != INVALIDATED_PROOF
                }) {
                    replaced.insert((start, row_hash));
                }
            }
        }
        for held in &mut entry.proved {
            if replaced.contains(&(held.bucket, held.row)) {
                held.proof = REPLACED_PROOF;
                held.account = None;
            }
        }
        !replaced.is_empty()
    }
    pub(crate) fn record_proved(&mut self, body: &Value, witnessed: bool, missing: &[String]) {
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
        // `record` normally settled (and LRU-refreshed) this ACK's session;
        // refreshing again would only churn persisted bytes.
        if self.session_mut(session).is_none() {
            self.session_entry(session, true);
        }
        let Some(entry) = self.session_mut(session) else {
            return;
        };
        let key = entry.bound_key().clone();
        let mut proved = std::mem::take(&mut entry.proved)
            .into_iter()
            .map(|entry| ((entry.bucket, entry.row), (entry.proof, entry.account)))
            .collect::<BTreeMap<_, _>>();
        let mut pending = std::mem::take(&mut entry.missing)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut present = BTreeSet::new();
        let mut marked = BTreeSet::new();
        for bucket in buckets {
            let Some(start) = bucket["bucket_start"].as_str().and_then(bucket_key) else {
                continue;
            };
            present.insert(start);
            for row in bucket["model_usage"].as_array().into_iter().flatten() {
                let Some(row_key) = wire_row_key(row) else {
                    continue;
                };
                let row_hash = proved_row_hash(&key, &row_key);
                if row["identity_retained"] == json!(true) {
                    marked.insert((start, row_hash));
                    continue;
                }
                if !witnessed {
                    continue;
                }
                if let Some(proof) = row_proof(&key, row, &body["request_evidence"]) {
                    let account = match row["account_identifier_hash"].as_str() {
                        Some(hash) => match digest_hex::decode::<serde::de::value::Error>(hash) {
                            Ok(hash) => Some(hash),
                            Err(_) => continue,
                        },
                        None => None,
                    };
                    proved.insert((start, row_hash), (proof, account));
                    pending.remove(&start);
                }
            }
        }
        proved.retain(|(bucket, _), _| present.contains(bucket));
        pending.retain(|bucket| present.contains(bucket));
        let mut received = 0u64;
        for start in missing.iter().filter_map(|start| bucket_key(start)) {
            received += 1;
            proved.retain(|row, _| row.0 != start || !marked.contains(row));
            if marked.iter().any(|(bucket, _)| *bucket == start) {
                pending.insert(start);
            }
        }
        let mut capped = 0u64;
        // Evict whole oldest buckets: a lost row only means fresh tags later.
        while proved.len() > MAX_PROVED_ROWS {
            let oldest = proved.keys().next().expect("nonempty").0;
            let before = proved.len();
            proved.retain(|(bucket, _), _| *bucket != oldest);
            capped += (before - proved.len()) as u64;
        }
        while pending.len() > MAX_PENDING_MISSING {
            pending.pop_first();
        }
        entry.proved = proved
            .into_iter()
            .map(|((bucket, row), (proof, account))| ProvedRow {
                bucket,
                row,
                proof,
                account,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .into_vec();
        entry.missing = pending
            .into_iter()
            .collect::<Vec<_>>()
            .into_boxed_slice()
            .into_vec();
        if received > 0 || capped > 0 {
            super::budget::record(&super::budget::Counts {
                retained_proof_missing_received: received,
                proved_rows_capped: capped,
                ..Default::default()
            });
        }
    }
    /// Segment ledger only, after the live body of `live_body` was recorded:
    /// its cut is now accepted, so entries of this session at or past its
    /// `through` (or all of them when it carries none: a whole body retired
    /// the segments) leave. Never by count or recency.
    pub(crate) fn retire(&mut self, live_body: &Value) {
        let (Some(key), Some(live)) = (self.1.as_ref(), live_body["source_session_id"].as_str())
        else {
            return;
        };
        if !self.5 || live_body["history_segment"].is_object() {
            return;
        }
        let of = session_key(key, live);
        let through = live_body["history_segments"]["through"]
            .as_str()
            .and_then(bucket_key);
        self.0.retain(|_, entry| {
            entry.of.as_deref() != Some(of.as_str())
                || through
                    .is_some_and(|through| entry.starts.last().map_or(true, |last| *last < through))
        });
    }
    /// Segment ledger: retire a session's entries once a complete census
    /// references none of their ACKed bodies (the session is gone). A
    /// session that still has one referenced segment, or any item on this
    /// page (`page`: live session ids), keeps all of them.
    pub(crate) fn retire_absent(&mut self, absent: &BTreeSet<String>, page: &BTreeSet<&str>) {
        if !self.5 || absent.is_empty() {
            return;
        }
        let Some(key) = self.1.as_ref() else {
            return;
        };
        let mut present = page
            .iter()
            .map(|live| session_key(key, live))
            .collect::<BTreeSet<_>>();
        for entry in self.0.values() {
            if !entry
                .fingerprint
                .as_ref()
                .is_some_and(|fingerprint| absent.contains(fingerprint))
            {
                present.extend(entry.of.clone());
            }
        }
        self.0
            .retain(|_, entry| entry.of.as_ref().map_or(true, |of| present.contains(of)));
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    /// Copy-prefix ENABLE guard (Lead B F3): whether a stored-body ACK
    /// may have frozen `session`'s bucket at `bucket_start`. Known hints
    /// answer exactly; incomplete hints (whole buckets evicted) or an
    /// unparsable start answer yes. Without hints for the session the answer
    /// is no, the same reach as #909's own protection (`accepted_state_unknown`).
    pub(crate) fn may_have_accepted(&self, session: &str, bucket_start: &str) -> bool {
        self.get(session).is_some_and(|state| {
            state.incomplete
                || bucket_key(bucket_start)
                    .map_or(true, |start| state.binary_search(&start).is_ok())
        })
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
        self.record_with_diagnostics(body, true);
    }
    /// Pre-upload custody sizing must not report hypothetical evictions.
    pub(crate) fn preview_record(&mut self, body: &Value) {
        self.record_with_diagnostics(body, false);
    }
    fn record_with_diagnostics(&mut self, body: &Value, report: bool) {
        if self.1.is_none() {
            return;
        }
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
        let item_cap = self.4;
        let limit = max_shares(item_cap);
        let segments = self.5;
        let segment_of = body["history_segment"]["of"]
            .as_str()
            .zip(self.1.as_ref())
            .map(|(live, key)| session_key(key, live));
        let entry = self
            .session_entry(session, report)
            .expect("bound fingerprint key");
        if segments {
            entry.of = segment_of;
            entry.fingerprint = body["snapshot_fingerprint"].as_str().map(str::to_owned);
        }
        let mut shares = if item_cap > MAX_ITEM_BYTES {
            entry.shares_after(body, entry.shares.iter().cloned())
        } else {
            let prior = std::mem::take(&mut entry.shares);
            entry.shares_after(body, prior.into_iter())
        };
        // An increased-cap upload is preflighted before POST. Preserve prior
        // proof defensively if an unexpected ACK would exceed its bound.
        if item_cap > MAX_ITEM_BYTES && shares.len() > limit {
            entry.incomplete = true;
            return;
        }
        // Evict whole buckets, never a partial share set masquerading as a
        // complete accepted fingerprint. Loss takes the counted unknown path.
        while shares.len() > limit {
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
/// A segment's accepted hints for its `buckets`: per bucket its own entry
/// when that holds the bucket, else the live entry's shares (windows are
/// fixed, so no other segment ever held it).
/// Retained proof comes from its own entry only: until the segment entity
/// has its own accepted proof it sends full identity rows.
pub(crate) fn segment_view(
    own: Option<&AcceptedSession>,
    live: Option<&AcceptedSession>,
    buckets: &[i64],
) -> Option<AcceptedSession> {
    let base = own.or(live)?;
    let mut view = AcceptedSession {
        key_epoch: base.key_epoch,
        key: base.key.clone(),
        incomplete: own.is_some_and(|own| own.incomplete),
        ..Default::default()
    };
    let mut buckets = buckets.to_vec();
    buckets.sort_unstable();
    buckets.dedup();
    for bucket in buckets {
        let holder = own
            .into_iter()
            .chain(live)
            .find(|entry| entry.starts.binary_search(&bucket).is_ok());
        if let Some(holder) = holder {
            view.starts.push(bucket);
            let first = holder.shares.partition_point(|share| share.bucket < bucket);
            view.shares.extend(
                holder.shares[first..]
                    .iter()
                    .take_while(|share| share.bucket == bucket)
                    .cloned(),
            );
        } else if live.is_some_and(|live| live.incomplete) {
            view.incomplete = true;
        }
        if let Some(own) = own {
            let first = own.proved.partition_point(|row| row.bucket < bucket);
            view.proved.extend(
                own.proved[first..]
                    .iter()
                    .take_while(|row| row.bucket == bucket)
                    .cloned(),
            );
            if own.missing.binary_search(&bucket).is_ok() {
                view.missing.push(bucket);
            }
        }
    }
    Some(view)
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
        )?;
        c.add(
            self.proved
                .capacity()
                .checked_mul(std::mem::size_of::<ProvedRow>())?,
        )?;
        c.add(
            self.missing
                .capacity()
                .checked_mul(std::mem::size_of::<i64>())?,
        )?;
        c.add(self.of.as_ref().map_or(0, String::capacity))?;
        c.add(self.fingerprint.as_ref().map_or(0, String::capacity))
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
                    json!({"key_epoch":digest_hex::encode(&key_epoch(&fixture_key())),"starts":[],"shares":[]}),
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
                            last_ack: 0,
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
                            of: None,
                            fingerprint: None,
                            proved: Vec::new(),
                            missing: Vec::new(),
                        },
                    )
                })
                .collect(),
            None,
            false,
            false,
            0,
            false,
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

        // [money] The receiver's 2 MiB formula admits exactly 6,553 shares.
        // Existing OFF assertions above retain the released 1,536 behavior.
        let mut enlarged = body.clone();
        enlarged["usage_buckets"] = json!((0..2_185)
            .map(|hour| json!({
                "bucket_start":(start+time::Duration::hours(hour)).format(&Rfc3339).unwrap(),
                "model_usage":[{"model":"claude-synthetic","identity_parts":
                    (0..if hour == 2_184 { 1 } else { 3 }).map(|key| json!({
                        "evidence_ref":0,"account_identifier_hash":format!("{key:064x}")
                    })).collect::<Vec<_>>()}]
            }))
            .collect::<Vec<_>>());
        let mut state = AcceptedBuckets::for_test();
        state.set_item_cap(2 * 1024 * 1024);
        assert_eq!(max_shares(2 * 1024 * 1024), 6_553);
        state.record(&enlarged);
        let known = state.get("bounded-shares").unwrap();
        assert_eq!(known.shares.len(), 6_553);
        assert!(!known.incomplete);
        assert_eq!(known.starts.len(), 2_185);
        assert_eq!(
            known
                .row_shares(
                    start.unix_timestamp(),
                    &wire_row_key(&enlarged["usage_buckets"][0]["model_usage"][0]).unwrap()
                )
                .len(),
            3
        );
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut restored = AcceptedBuckets::restore_for_test(&bytes);
        restored.set_item_cap(2 * 1024 * 1024);
        restored.record(&enlarged);
        assert_eq!(restored.get("bounded-shares").unwrap().shares, known.shares);
        assert!(!restored.get("bounded-shares").unwrap().incomplete);
        // A settled-history segment entry keeps the same raised-cap shares.
        let mut segment = enlarged.clone();
        segment["source_session_id"] = json!("bounded-shares#w20260827");
        segment["history_segment"] = json!({"of":"bounded-shares"});
        let mut segments = AcceptedBuckets::segments_for_test();
        segments.set_item_cap(2 * 1024 * 1024);
        segments.record(&segment);
        let own = segments.get("bounded-shares#w20260827").unwrap();
        assert_eq!(own.shares, known.shares);
        assert!(!own.incomplete);
        if crate::heap_layout_bound::layout_supported() {
            assert!(crate::heap_layout_bound::bound(&restored, 100_000).is_none());
            assert!(crate::heap_layout_bound::bound(&restored, usize::MAX).unwrap() > 500_000);
        }
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
            .unwrap()["key_epoch"] = json!("0".repeat(64));
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

#[cfg(test)]
mod eviction_tests {
    use super::*;
    #[test]
    fn last_ack_lru_survives_restart_and_counts_eviction_separately() {
        let mut state = AcceptedBuckets::for_test();
        let body = |session: usize| {
            let mut body = tests::body(true);
            body["source_session_id"] = json!(format!("lru-{session}"));
            body
        };
        super::super::take_identity_counts();
        for session in 0..MAX_SESSIONS {
            let body = body(session);
            state.record(&body);
            state.record_proved(&body, true, &[]);
        }
        state.record(&body(0)); // refresh the oldest before restart
        let mut restored = AcceptedBuckets::restore_for_test(&serde_json::to_vec(&state).unwrap());
        restored.record(&body(MAX_SESSIONS));
        restored.record_proved(&body(MAX_SESSIONS), true, &[]);
        assert_eq!(
            restored.get("lru-0").unwrap().proved[0].account,
            Some([0xaa; 32])
        );
        assert_eq!(
            restored
                .0
                .values()
                .map(|entry| entry.proved.len())
                .sum::<usize>(),
            MAX_SESSIONS
        );
        assert!(restored.get("lru-0").is_some());
        assert!(restored.get("lru-1").is_none());
        assert!(restored.get(&format!("lru-{MAX_SESSIONS}")).is_some());
        assert!(restored.get("brand-new").is_none());
        let counts = serde_json::to_value(super::super::take_identity_counts()).unwrap();
        assert_eq!(counts["identity_cap"]["accepted_state_evicted"], 1);
        assert_eq!(counts["identity_cap"]["accepted_state_unknown"], 0);
        assert_eq!(restored.0.len(), MAX_SESSIONS);
    }
}

#[cfg(test)]
mod retained_tests {
    use super::*;
    fn body(row: Value) -> Value {
        json!({"source_session_id":"synthetic", "provenance":{"collector":COLLECTOR},
            "request_evidence":[{"identity_basis":TELEMETRY_LOGIN}],
            "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z","model_usage":[row]}]})
    }
    fn tagged(login: &str, requests: u64) -> Value {
        json!({"model":"claude-synthetic","request_count":requests,"evidence_ref":0,
            "account_identifier_hash":login})
    }
    fn proof(state: &AcceptedBuckets) -> Option<[u8; 16]> {
        let row = wire_row_key(&json!({"model":"claude-synthetic"})).unwrap();
        state
            .get("synthetic")?
            .proved_row(bucket_key("2026-09-01T10:00:00Z").unwrap(), &row)
    }
    #[test]
    fn witnessed_positive_tags_enter_latest_proof_wins_and_markers_keep_it() {
        let mut state = AcceptedBuckets::for_test();
        let a = body(tagged(&"a".repeat(64), 1));
        state.record_proved(&a, false, &[]);
        assert_eq!(proof(&state), None, "unwitnessed ACK never adds");
        assert!(state.get("synthetic").unwrap().proved.is_empty());
        state.record_proved(&a, true, &[]);
        assert_eq!(
            state.get("synthetic").unwrap().proved[0].account,
            Some([0xaa; 32])
        );
        let first = proof(&state).unwrap();
        let b = body(tagged(&"b".repeat(64), 1));
        state.record_proved(&b, true, &[]);
        let second = proof(&state).unwrap();
        assert_ne!(first, second, "a different positive proof replaces");
        state.record_proved(&body(tagged(&"b".repeat(64), 2)), true, &[]);
        assert_ne!(
            proof(&state).unwrap(),
            second,
            "amounts are part of the proof"
        );
        state.record_proved(&b, true, &[]);
        for untagged in [
            json!({"model":"claude-synthetic","request_count":1}),
            json!({"model":"claude-synthetic","request_count":1,"identity_retained":true}),
        ] {
            state.record_proved(&body(untagged), true, &[]);
            assert_eq!(proof(&state), Some(second), "server keeps proof");
        }
        // A replacement upload drops a different held proof before the POST;
        // equal proof, markers and untagged rows never do.
        let mut sent = state.clone();
        assert!(!sent.invalidate_replaced(&b));
        assert!(!sent.invalidate_replaced(&body(
            json!({"model":"claude-synthetic","request_count":1,"identity_retained":true})
        )));
        assert!(sent.invalidate_replaced(&a));
        assert_eq!(sent.proved_rows_for_test("synthetic"), Some((0, 0)));
        // The tombstone outlives a restart, re-sends do not churn it, and it
        // holds no class H hash; the replacement's ACK settles it.
        let held = &sent.get("synthetic").unwrap().proved;
        assert_eq!((held[0].proof, held[0].account), (REPLACED_PROOF, None));
        let mut restored = AcceptedBuckets::restore_for_test(&serde_json::to_vec(&sent).unwrap());
        assert_eq!(restored.proved_rows_for_test("synthetic"), Some((0, 0)));
        let (row, start) = (
            wire_row_key(&json!({"model":"claude-synthetic"})).unwrap(),
            bucket_key("2026-09-01T10:00:00Z").unwrap(),
        );
        let settled = |state: &AcceptedBuckets| {
            state
                .get("synthetic")
                .unwrap()
                .replacement_unsettled(start, &row)
        };
        assert!(settled(&restored));
        assert!(!restored.invalidate_replaced(&a));
        restored.record_proved(&a, true, &[]);
        assert!(!settled(&restored));
        assert_eq!(
            restored.get("synthetic").unwrap().proved[0].account,
            Some([0xaa; 32])
        );
        assert_eq!(restored.proved_rows_for_test("synthetic"), Some((1, 0)));
        // retained_proof_missing removes only rows this body marked.
        state.record_proved(&b, true, &["2026-09-01T10:00:00Z".into()]);
        assert_eq!(proof(&state), Some(second));
        let marked =
            body(json!({"model":"claude-synthetic","request_count":1,"identity_retained":true}));
        state.record_proved(&marked, true, &["2026-09-01T10:00:00Z".into()]);
        assert_eq!(proof(&state), None);
        assert_eq!(state.proved_rows_for_test("synthetic"), Some((0, 1)));
        assert!(
            state.get("synthetic").unwrap().proved.is_empty(),
            "missing grain drops class H too"
        );
        state.record_proved(&b, true, &[]);
        assert_eq!(state.proved_rows_for_test("synthetic"), Some((1, 0)));
        // A bucket the body no longer has leaves with it; legacy bodies never touch.
        let mut legacy = b.clone();
        legacy["provenance"]["collector"] = json!("legacy");
        legacy["usage_buckets"] = json!([]);
        state.record_proved(&legacy, true, &[]);
        assert_eq!(state.proved_rows_for_test("synthetic"), Some((1, 0)));
        let mut gone = b.clone();
        gone["usage_buckets"] = json!([]);
        state.record_proved(&gone, true, &[]);
        assert_eq!(state.proved_rows_for_test("synthetic"), Some((0, 0)));
    }
    #[test]
    fn gate_off_state_bytes_are_unchanged_and_proved_rows_survive_restart() {
        let mut off = AcceptedBuckets::for_test();
        off.record(&body(tagged(&"a".repeat(64), 1)));
        let bytes = serde_json::to_string(&off).unwrap();
        assert!(!bytes.contains("proved") && !bytes.contains("missing"));
        let mut on = off.clone();
        on.record_proved(&body(tagged(&"a".repeat(64), 1)), true, &[]);
        let encoded = serde_json::to_vec(&on).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains(&"a".repeat(64)));
        let restored = AcceptedBuckets::restore_for_test(&encoded);
        assert_eq!(restored, on);
        assert!(
            !restored.retained_enabled(),
            "capability is never persisted"
        );
        let compact: Value = serde_json::from_slice(&encoded).unwrap();
        let session = compact.as_object().unwrap().values().next().unwrap();
        assert_eq!(session["proved"].as_str().unwrap().len(), 103);
        for corrupt in [json!("0".repeat(79)), json!("G".repeat(80)), json!([1])] {
            let mut bad = compact.clone();
            for state in bad.as_object_mut().unwrap().values_mut() {
                state["proved"] = corrupt.clone();
            }
            let mut dropped: AcceptedBuckets = serde_json::from_value(bad).unwrap();
            dropped.bind_test_key(Some([0x42; 32]));
            assert!(
                dropped.is_empty(),
                "malformed proved rows drop only the hint"
            );
        }
        let mut rotated: AcceptedBuckets = serde_json::from_slice(&encoded).unwrap();
        rotated.bind_test_key(Some([0x43; 32]));
        assert!(rotated.is_empty(), "a rotated key drops proved rows too");
        let mut cleared = restored;
        cleared.clear_retained();
        assert_eq!(cleared.proved_rows_for_test("synthetic"), Some((0, 0)));
        assert_eq!(serde_json::to_string(&cleared).unwrap(), bytes);
    }
    #[test]
    fn proved_rows_evict_whole_oldest_buckets_at_the_bound() {
        let start = OffsetDateTime::parse("2026-09-01T00:00:00Z", &Rfc3339).unwrap();
        let mut value = body(Value::Null);
        value["usage_buckets"] = json!((0..MAX_PROVED_ROWS / 2 + 1)
            .map(|hour| json!({
                "bucket_start":(start + time::Duration::hours(hour as i64)).format(&Rfc3339).unwrap(),
                "model_usage":[tagged(&"a".repeat(64), 1), {
                    "model":"claude-other","request_count":1,"evidence_ref":0,
                    "account_identifier_hash":"a".repeat(64)}]
            }))
            .collect::<Vec<_>>());
        let mut state = AcceptedBuckets::for_test();
        super::super::take_identity_counts();
        state.record_proved(&value, true, &[]);
        assert_eq!(
            super::super::take_identity_counts()
                .identity_cap
                .proved_rows_capped,
            2
        );
        let known = state.get("synthetic").unwrap();
        assert_eq!(known.proved.len(), MAX_PROVED_ROWS);
        assert_eq!(known.proved.capacity(), MAX_PROVED_ROWS);
        assert!(known
            .proved
            .iter()
            .all(|row| row.bucket != start.unix_timestamp()));
    }
}

#[cfg(all(test, target_pointer_width = "64"))]
mod retained_heap_tests {
    use super::*;
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    #[test]
    fn maximum_ledger_with_proved_rows_has_a_four_mib_heap_bound() {
        let state = AcceptedBuckets(
            (0..MAX_SESSIONS)
                .map(|n| {
                    (
                        format!("{n:064x}"),
                        AcceptedSession {
                            key_epoch: [0; 32],
                            key: None,
                            last_ack: 0,
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
                            of: None,
                            fingerprint: None,
                            proved: vec![
                                ProvedRow {
                                    bucket: 1,
                                    row: [0; 16],
                                    proof: [0; 16],
                                    account: Some([255; 32]),
                                };
                                MAX_PROVED_ROWS
                            ],
                            missing: (0..MAX_PENDING_MISSING as i64).collect(),
                        },
                    )
                })
                .collect(),
            None,
            false,
            false,
            0,
            false,
        );
        let mut counter = Counter::new(4 * 1024 * 1024);
        counter.add(std::mem::size_of_val(&state)).unwrap();
        state.heap_bound(&mut counter).unwrap();
        assert_eq!(std::mem::size_of::<ProvedRow>(), 80);
        assert!(counter.bytes <= 4_010_000, "layout={}", counter.bytes);
        eprintln!(
            "accepted-share+proved-row requested-layout maximum={} bytes",
            counter.bytes
        );
    }
}

#[cfg(test)]
mod segment_tests {
    use super::*;
    const OLD: &str = "2026-08-28T10:00:00Z";
    const LATE: &str = "2026-08-29T10:00:00Z";
    const NEW: &str = "2026-09-29T10:00:00Z";
    const LIVE: &str = "synthetic";
    const SEGMENT: &str = "synthetic#w20260827";
    fn body(session: &str, starts: &[&str], account: char, extra: Value) -> Value {
        let mut body = json!({"source_session_id": session, "provenance": {"collector": COLLECTOR},
            "request_evidence": [{"identity_basis": TELEMETRY_LOGIN}],
            "usage_buckets": starts.iter().map(|start| json!({"bucket_start": start, "model_usage": [
                {"model": "claude-synthetic", "evidence_ref": 0, "input_tokens": 1,
                 "account_identifier_hash": account.to_string().repeat(64)}]})).collect::<Vec<_>>()});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    }
    fn row() -> RowKey {
        wire_row_key(&json!({"model": "claude-synthetic"})).unwrap()
    }
    fn of() -> Value {
        json!({"history_segment": {"of": LIVE}})
    }

    /// [money] A segment's own entry wins per bucket; a bucket
    /// it lacks (late in its window, or a lost live ACK) takes the live
    /// entry's shares; retained proof is the segment's own only.
    #[test]
    fn segment_view_falls_back_per_bucket_and_keeps_proof_its_own() {
        let mut live = AcceptedBuckets::for_test();
        live.record(&body(LIVE, &[OLD, LATE], 'b', json!({})));
        let mut proving = live.clone();
        proving.record_proved(&body(LIVE, &[OLD, LATE], 'b', json!({})), true, &[]);
        let mut segments = AcceptedBuckets::segments_for_test();
        segments.record(&body(SEGMENT, &[OLD], 'a', of()));
        let (old, late) = (bucket_key(OLD).unwrap(), bucket_key(LATE).unwrap());
        let own = segments.get(SEGMENT);
        let view = segment_view(own, proving.get(LIVE), &[late, old]).unwrap();
        assert_eq!(&*view, &[old, late]);
        assert_eq!(
            view.row_shares(old, &row()),
            own.unwrap().row_shares(old, &row())
        );
        assert_eq!(
            view.row_shares(late, &row()),
            live.get(LIVE).unwrap().row_shares(late, &row())
        );
        assert_ne!(view.row_shares(old, &row()), view.row_shares(late, &row()));
        assert!(proving.get(LIVE).unwrap().proved_row(old, &row()).is_some());
        assert!(view.proved_row(old, &row()).is_none() && view.proved_row(late, &row()).is_none());
        assert!(segment_view(None, None, &[old]).is_none());
    }

    /// [money] Segment entries are never evicted by count (only an
    /// alarm above the design maximum) and leave only with their session's
    /// cut: a live body past their window keeps them, a live body whose cut
    /// is lower (or absent) retires them.
    #[test]
    fn segment_entries_leave_only_with_their_session_cut() {
        let mut segments = AcceptedBuckets::segments_for_test();
        for n in 0..=SEGMENT_DESIGN_MAX {
            segments.record(&body(
                &format!("other{n}#w20260827"),
                &[OLD],
                'a',
                json!({"history_segment": {"of": format!("other{n}")}}),
            ));
        }
        segments.record(&body(SEGMENT, &[OLD], 'a', of()));
        assert_eq!(segments.len(), SEGMENT_DESIGN_MAX + 2);
        assert_eq!(
            super::super::budget::take_counts().accepted_segments_over_design,
            2
        );
        let live = |through: Option<&str>| {
            body(
                LIVE,
                &[NEW],
                'a',
                through.map_or(
                    json!({}),
                    |through| json!({"history_segments": {"through": through, "count": 1}}),
                ),
            )
        };
        segments.retire(&live(Some("2026-09-03T00:00:00Z")));
        assert!(segments.get(SEGMENT).is_some());
        segments.retire(&live(Some("2026-08-27T00:00:00Z")));
        assert!(segments.get(SEGMENT).is_none());
        segments.record(&body(SEGMENT, &[OLD], 'a', of()));
        segments.retire(&live(None));
        assert!(segments.get(SEGMENT).is_none());
        assert_eq!(segments.len(), SEGMENT_DESIGN_MAX + 1);
    }

    /// [format] The sibling field decodes every entry (no session cap) and
    /// keeps each entry's live link; the live map keeps its cap.
    #[test]
    fn segment_ledger_decodes_uncapped_with_its_live_link() {
        let mut segments = AcceptedBuckets::segments_for_test();
        for n in 0..(MAX_SESSIONS + 4) {
            segments.record(&body(&format!("{LIVE}{n}#w20260827"), &[OLD], 'a', of()));
        }
        let bytes = serde_json::to_vec(&segments).unwrap();
        let mut decoded =
            decode_segments(&mut serde_json::Deserializer::from_slice(&bytes)).unwrap();
        decoded.bind_test_key(Some([0x42; 32]));
        assert_eq!(decoded, segments);
        let capped = AcceptedBuckets::restore_for_test(&bytes);
        assert_eq!(capped.len(), MAX_SESSIONS);
    }

    /// [money] Segment entries leave with their session: a complete census
    /// that references none of a session's ACKed segment bodies retires all
    /// of them; one still referenced, or any item of the session on the page,
    /// keeps the whole session's entries.
    #[test]
    fn segment_entries_retire_when_a_complete_census_lost_their_session() {
        let mut segments = AcceptedBuckets::segments_for_test();
        let fingerprint = |n: u8| {
            json!({"history_segment": {"of": LIVE},
            "snapshot_fingerprint": format!("{n:064x}")})
        };
        segments.record(&body(SEGMENT, &[OLD], 'a', fingerprint(1)));
        segments.record(&body("synthetic#w20260903", &[NEW], 'a', fingerprint(2)));
        segments.record(&body(
            "other#w20260827",
            &[OLD],
            'a',
            json!({"history_segment": {"of": "other"}, "snapshot_fingerprint": format!("{:064x}", 3)}),
        ));
        let none = BTreeSet::new();
        segments.retire_absent(&BTreeSet::from([format!("{:064x}", 1)]), &none);
        assert_eq!(segments.len(), 3);
        let both = BTreeSet::from([format!("{:064x}", 1), format!("{:064x}", 2)]);
        // Changed bodies of a session still on the page are not its absence.
        segments.retire_absent(&both, &BTreeSet::from([LIVE]));
        assert_eq!(segments.len(), 3);
        segments.retire_absent(&both, &none);
        assert_eq!(segments.len(), 1);
        assert!(segments.get(SEGMENT).is_none() && segments.get("other#w20260827").is_some());
    }
}

#[cfg(all(test, target_pointer_width = "64"))]
mod segment_heap_tests {
    use super::*;
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    /// [format] Heap bound of the sibling segment ledger at its stated
    /// design maximum: 64 entries, each at MAX_SHARES with full proof. A real
    /// entry spans one 7-day window (at most 168 hourly buckets).
    #[test]
    fn segment_ledger_at_its_design_maximum_has_a_fourteen_mib_heap_bound() {
        let key = fixture_key();
        let mut state = AcceptedBuckets::segments_for_test();
        for n in 0..SEGMENT_DESIGN_MAX {
            let starts = (0..MAX_SHARES as i64).collect::<Vec<_>>();
            state.0.insert(
                session_key(&key, &format!("max-{n}#w20260827")),
                AcceptedSession {
                    key_epoch: key_epoch(&key),
                    key: Some(key.clone()),
                    last_ack: u64::MAX,
                    shares: starts
                        .iter()
                        .map(|bucket| AcceptedShare {
                            bucket: *bucket,
                            row: [255; 32],
                            authority: Some([255; 32]),
                        })
                        .collect(),
                    proved: (0..MAX_PROVED_ROWS as i64)
                        .map(|bucket| ProvedRow {
                            bucket,
                            row: [255; 16],
                            proof: [255; 16],
                            account: Some([255; 32]),
                        })
                        .collect(),
                    missing: (0..MAX_PENDING_MISSING as i64).collect(),
                    starts,
                    incomplete: true,
                    of: Some(session_key(&key, &format!("max-{n}"))),
                    fingerprint: Some("f".repeat(64)),
                },
            );
        }
        let mut counter = Counter::new(16 * 1024 * 1024);
        counter.add(std::mem::size_of_val(&state)).unwrap();
        state.heap_bound(&mut counter).unwrap();
        assert!(counter.bytes < 14 * 1024 * 1024, "{}", counter.bytes);
    }
}
