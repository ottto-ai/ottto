// Frozen complete ScanIndexEntry codec, identical at both released source pins:
// 0.1.201 f174d111fbcdfb0ab9c2abeb299c12d50b435c29
// 0.1.202 79488a7297817edfe1eb5cfc34b779408d511726
// Original `pub struct ScanIndexEntry { ... }` plus newline SHA-256:
// bfc03bb32dfec991075afffa371183519c6123ff46749c215b38efd02288e169
// Owner/AppliedTierReceipt decode paths copied unchanged; enclosing imports only.
use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIndexEntry {
    pub size_bytes: u64,
    pub modified_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_unix_nanos: Option<u64>,
    pub source_file_fingerprint: String,
    pub last_snapshot_fingerprint: Option<String>,
    /// Local-only witness for additive wire evidence intentionally excluded
    /// from semantic identity. This lets an absent/present/corrected context
    /// curve upload once without changing the server entity fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_upload_body_witness: Option<String>,
    /// Local projection revision that produced this file's settled body witness.
    /// Missing legacy revisions remain zero; zero preserves default scan behavior.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub effective_upload_body_witness_revision: u64,
    /// Marks entries written by the semantic-sync scan derivation. `None`
    /// identifies a pre-cutover entry that can be adopted without reparsing
    /// when transcript size and mtime are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_identity_version: Option<String>,
    /// Applied only through the existing common file/body acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_joined_member_set: Option<String>,
    /// Pending proof, captured before POST; never an applied/accepted witness.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_codex_protected_owner"
    )]
    pub codex_captured_joined_member_set: Option<String>,
    /// Hash-only logical owner for protecting joined/priced history from a
    /// state-only replacement after physical source retirement. No attribution.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_codex_protected_owner"
    )]
    pub codex_protected_owner: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "codex_file_join::deserialize_receipt"
    )]
    pub codex_applied_tier_receipt: Option<codex_file_join::AppliedTierReceipt>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub codex_applied_tier_receipt_required: bool,
    /// Captured selector evidence does not authorize a file/body checkpoint.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "codex_file_join::deserialize_receipt"
    )]
    pub codex_captured_tier_receipt: Option<codex_file_join::AppliedTierReceipt>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub codex_captured_tier_receipt_required: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub codex_captured_uncommitted: bool,
    /// Local-only Codex counting version of this entry's published body: set
    /// by a V2 writer together with `last_snapshot_fingerprint`, so selected
    /// saves, held-key restores and committable subsets move both as one entry.
    /// Older binaries drop it; an acknowledged entry without it stays Legacy.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub codex_counting_v2: bool,
    /// Hash-only session binding observed by a complete owned parse. Counting
    /// evidence follows this binding across physical moves; it grants no
    /// history protection or account authority.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_codex_protected_owner"
    )]
    pub codex_counting_owner: Option<String>,
    /// The ctime (unix nanos) in the opened-object identity that produced
    /// `source_file_fingerprint` (Claude and Codex only). With size, mtime
    /// and file birth unchanged the next scan rebuilds the identity from it,
    /// so a ctime-only change never triggers a re-read. Older binaries drop
    /// it; zero keeps the live-identity comparison once.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub(crate) opened_changed_nanos: u64,
    /// The file birth (unix nanos) of that open: the object generation the
    /// stored ctime belongs to. Zero (unavailable) never adopts the ctime.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub(crate) opened_birth_nanos: u64,
}
fn deserialize_codex_protected_owner<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(value.map(|value| value.as_str().unwrap_or("").to_owned()))
}
mod codex_file_join {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AppliedTierReceipt {
        version: u16,
        derivation: String,
        scope: String,
        records: usize,
        prefix_digest: String,
        tiers: BTreeMap<String, String>,
    }
    pub(super) fn deserialize_receipt<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<AppliedTierReceipt>, D::Error> {
        let value = Value::deserialize(deserializer)?;
        if value.is_null() {
            return Ok(None);
        }
        // A future/malformed local receipt must hold its file, rather than make
        // the ordinary index decoder discard every protected file as corruption.
        Ok(Some(serde_json::from_value(value).unwrap_or_else(|_| {
            AppliedTierReceipt {
                version: u16::MAX,
                derivation: String::new(),
                scope: String::new(),
                records: 0,
                prefix_digest: String::new(),
                tiers: BTreeMap::new(),
            }
        })))
    }
}
