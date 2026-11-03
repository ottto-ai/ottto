//! Decode-only compatibility for retired whole-file refusal state.
use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Debt {
    content_hash: String,
    observations: usize,
    #[serde(default)]
    size_bytes: u64,
    #[serde(default = "sampled_scan::now_seconds")]
    first_seen_unix_seconds: u64,
}
crate::heap_layout_bound::fields!(Debt; content_hash, observations, size_bytes, first_seen_unix_seconds);
