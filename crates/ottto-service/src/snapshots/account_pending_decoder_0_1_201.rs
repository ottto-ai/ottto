// Frozen account-pending record codec from the 0.1.201 source pin
// f174d111fbcdfb0ab9c2abeb299c12d50b435c29, snapshots.rs:4454-4723.
// Old lenient_decode.rs:1657-1659 decodes each pending record with this codec.
// Keep this copy frozen; it deliberately does not use the current record types.
use super::*;

const CLAUDE_ACCOUNT_REQUEST_SET_VERSION: &str = "claude_account_request_set:v2";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeAccountRequestSet {
    /// Sorted 8-byte SHA-256 prefixes, packed as base64 (no JSON byte arrays).
    prefixes: String,
    /// Full-hash-set commitment: equal prefixes never hide a changed full set.
    fingerprint: String,
    /// Exact source/entity/body revision that finalized with this account.
    identity_revision: Option<String>,
}

impl Serialize for ClaudeAccountRequestSet {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let digest = &self.fingerprint;
        let revision = self
            .identity_revision
            .as_deref()
            .map(|value| format!(":{value}"))
            .unwrap_or_default();
        serializer.serialize_str(&format!("{}:{digest}{revision}", self.prefixes))
    }
}
impl<'de> Deserialize<'de> for ClaudeAccountRequestSet {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let (prefixes, commitment) = value
            .split_once(':')
            .ok_or_else(|| serde::de::Error::custom("invalid account request-set encoding"))?;
        let (digest, identity_revision) = commitment
            .split_once(':')
            .map_or((commitment, None), |(digest, revision)| {
                (digest, Some(revision))
            });
        if identity_revision.is_some_and(|revision| {
            revision.len() != 64
                || !revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(serde::de::Error::custom(
                "invalid account identity revision",
            ));
        }
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "invalid account request-set digest",
            ));
        }
        Ok(Self {
            prefixes: prefixes.to_string(),
            fingerprint: digest.to_string(),
            identity_revision: identity_revision.map(str::to_string),
        })
    }
}

impl ClaudeAccountRequestSet {
    fn from_full_hashes(hashes: &BTreeSet<String>) -> Option<Self> {
        use base64::Engine as _;
        let mut packed = Vec::with_capacity(hashes.len().checked_mul(8)?);
        let mut previous = None;
        for hash in hashes {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return None;
            }
            let prefix = u64::from_str_radix(&hash[..16], 16).ok()?;
            if previous == Some(prefix) {
                // Two different full hashes sharing a prefix are a hold.
                return None;
            }
            packed.extend_from_slice(&prefix.to_be_bytes());
            previous = Some(prefix);
        }
        Some(Self {
            prefixes: base64::engine::general_purpose::STANDARD_NO_PAD.encode(packed),
            fingerprint: claude_request_id_set_fingerprint(hashes),
            identity_revision: None,
        })
    }

    fn unpack(&self) -> Option<Vec<u8>> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.prefixes)
            .ok()?;
        (bytes.len() % 8 == 0
            && bytes
                .chunks_exact(8)
                .zip(bytes.chunks_exact(8).skip(1))
                .all(|(left, right)| left < right)
            && is_snapshot_fingerprint(&self.fingerprint))
        .then_some(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "ClaudeAccountFamilyPendingWire")]
struct ClaudeAccountFamilyPendingWindow {
    version: String,
    census_window_end: String,
    account_identifier_hash: String,
    evidence_request_count: u128,
    census_complete: bool,
    members: BTreeMap<String, u64>,
    member_requests: BTreeMap<String, ClaudeAccountRequestSet>,
    invalid: bool,
}

impl Serialize for ClaudeAccountFamilyPendingWindow {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("v", &self.version)?;
        map.serialize_entry("census_window_end", &self.census_window_end)?;
        map.serialize_entry("account_identifier_hash", &self.account_identifier_hash)?;
        map.serialize_entry("evidence_request_count", &self.evidence_request_count)?;
        // Older readers require these fields. They ignore v/r/archives and
        // decode empty full-hash evidence without quarantining the index.
        map.serialize_entry("members", &self.members)?;
        if self.census_complete {
            map.serialize_entry("complete", &true)?;
        }
        map.serialize_entry("r", &self.member_requests)?;
        map.serialize_entry("invalid", &self.invalid)?;
        map.end()
    }
}

// Accept old full-hash records at the record boundary used by all three index
// decoders. First save writes only v2; unrelated persisted state is untouched.
#[derive(Deserialize)]
struct ClaudeAccountFamilyPendingWire {
    #[serde(default)]
    #[serde(rename = "v", alias = "version")]
    version: String,
    #[serde(default)]
    previous_windows: Vec<ClaudeAccountFamilyPendingWindow>,
    #[serde(default)]
    confirmed_absent_members: BTreeSet<String>,
    #[serde(rename = "w", alias = "census_window_end")]
    census_window_end: String,
    #[serde(rename = "a", alias = "account_identifier_hash")]
    account_identifier_hash: String,
    #[serde(rename = "e", alias = "evidence_request_count")]
    evidence_request_count: u128,
    #[serde(default, rename = "complete")]
    census_complete: bool,
    #[serde(default)]
    members: BTreeMap<String, u64>,
    #[serde(default)]
    #[serde(rename = "r", alias = "member_requests")]
    member_requests: BTreeMap<String, ClaudeAccountRequestSet>,
    #[serde(default)]
    member_request_id_hashes: BTreeMap<String, BTreeSet<String>>,
    #[serde(rename = "i", alias = "invalid")]
    invalid: bool,
}

impl From<ClaudeAccountFamilyPendingWire> for ClaudeAccountFamilyPendingWindow {
    fn from(wire: ClaudeAccountFamilyPendingWire) -> Self {
        let mut invalid = wire.invalid;
        let member_requests = if wire.version.is_empty() {
            invalid |= !wire.member_requests.is_empty();
            wire.member_request_id_hashes
                .into_iter()
                .filter_map(|(member, hashes)| {
                    match ClaudeAccountRequestSet::from_full_hashes(&hashes) {
                        Some(set) => Some((member, set)),
                        None => {
                            invalid = true;
                            None
                        }
                    }
                })
                .collect()
        } else {
            invalid |= wire.version != CLAUDE_ACCOUNT_REQUEST_SET_VERSION
                || !wire.member_request_id_hashes.is_empty()
                || wire
                    .member_requests
                    .values()
                    .any(|set| set.unpack().is_none());
            wire.member_requests
        };
        let members = if wire.version == CLAUDE_ACCOUNT_REQUEST_SET_VERSION {
            let derived = member_requests
                .iter()
                .filter_map(|(member, set)| {
                    set.unpack()
                        .map(|bytes| (member.clone(), (bytes.len() / 8) as u64))
                })
                .collect::<BTreeMap<_, _>>();
            if wire.members.is_empty() {
                derived
            } else {
                invalid |= wire.members != derived;
                wire.members
            }
        } else {
            wire.members
        };
        let mut pending = Self {
            version: CLAUDE_ACCOUNT_REQUEST_SET_VERSION.to_string(),
            census_window_end: wire.census_window_end,
            account_identifier_hash: wire.account_identifier_hash,
            evidence_request_count: wire.evidence_request_count,
            census_complete: wire.census_complete,
            members,
            member_requests,
            invalid,
        };
        pending.invalid |= !claude_family_request_ids_are_disjoint(&pending);
        pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ClaudeAccountFamilyPendingWire")]
struct ClaudeAccountFamilyPending {
    #[serde(flatten)]
    current: ClaudeAccountFamilyPendingWindow,
    /// Windows are retired only by save after newer identity bodies settle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    previous_windows: Vec<ClaudeAccountFamilyPendingWindow>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    confirmed_absent_members: BTreeSet<String>,
}

impl From<ClaudeAccountFamilyPendingWire> for ClaudeAccountFamilyPending {
    fn from(mut wire: ClaudeAccountFamilyPendingWire) -> Self {
        let previous_windows = std::mem::take(&mut wire.previous_windows);
        let confirmed_absent_members = std::mem::take(&mut wire.confirmed_absent_members);
        Self {
            current: wire.into(),
            previous_windows,
            confirmed_absent_members,
        }
    }
}

impl std::ops::Deref for ClaudeAccountFamilyPending {
    type Target = ClaudeAccountFamilyPendingWindow;
    fn deref(&self) -> &Self::Target {
        &self.current
    }
}
impl std::ops::DerefMut for ClaudeAccountFamilyPending {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.current
    }
}

fn claude_family_request_ids_are_disjoint(pending: &ClaudeAccountFamilyPendingWindow) -> bool {
    let expected = pending
        .members
        .values()
        .map(|count| u128::from(*count))
        .sum::<u128>();
    let mut union = BTreeSet::new();
    for (member, requests) in &pending.member_requests {
        let Some(packed) = requests.unpack() else {
            return false;
        };
        if pending.members.get(member).copied().map(u128::from) != Some((packed.len() / 8) as u128)
        {
            return false;
        }
        for prefix in packed.chunks_exact(8) {
            let prefix: [u8; 8] = prefix.try_into().expect("exact chunk");
            // Same full hash OR different full hashes sharing a prefix across
            // members: both hold the family, including across pages/reloads.
            if !union.insert(prefix) {
                return false;
            }
        }
    }
    expected > 0 && union.len() as u128 == expected
}

fn claude_request_id_set_fingerprint(request_id_hashes: &BTreeSet<String>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"claude_request_id_set:v1\0");
    for request_id_hash in request_id_hashes {
        digest.update(request_id_hash.as_bytes());
        digest.update(b"\0");
    }
    format!("{:x}", digest.finalize())
}

pub(super) fn assert_reads(bytes: &[u8], expected: &serde_json::Value) {
    let decoded: ClaudeAccountFamilyPending = serde_json::from_slice(bytes).unwrap();
    assert_eq!(&serde_json::to_value(decoded).unwrap(), expected);
}
