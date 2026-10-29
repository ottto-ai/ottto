// Frozen ScanIndexEntry serde codec from bf4d653b2165a95d04d337be4a058513d3163a18 (0.1.203).
// The old files-map loader delegates each entry to this derive. Keep frozen.
use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIndexEntry {
    pub size_bytes: u64,
    pub modified_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_unix_nanos: Option<u64>,
    pub source_file_fingerprint: String,
    pub last_snapshot_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_upload_body_witness: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub effective_upload_body_witness_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_identity_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_joined_member_set: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_codex_protected_owner"
    )]
    pub codex_captured_joined_member_set: Option<String>,
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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub codex_counting_v2: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_codex_protected_owner"
    )]
    pub codex_counting_owner: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub(crate) opened_changed_nanos: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub(crate) opened_birth_nanos: u64,
}
