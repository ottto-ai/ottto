//! One scan index entry: the stored listing stamp and Codex custody of a
//! single source file.

use super::serde_lenient::{deserialize_codex_counting_owner, deserialize_codex_protected_owner};
use crate::snapshots::*;
use crate::snapshots::{codex_file_join, codex_fragment};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanIndexEntry {
    /// RAM-only custody of a certified, already-observed Codex EOF fragment.
    /// Never serialized; missing evidence fails open to the existing read path.
    #[serde(skip)]
    pub(crate) codex_fragment: Option<Box<codex_fragment::BoundFragment>>,
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
        deserialize_with = "deserialize_codex_counting_owner"
    )]
    pub codex_counting_owner: Option<Box<str>>,
    /// The ctime (unix nanos) in the opened-object identity that produced
    /// `source_file_fingerprint` (all three sources). With size, mtime
    /// and file birth unchanged the next scan rebuilds the identity from it,
    /// so a ctime-only change never triggers a re-read. Older binaries drop
    /// it; zero keeps the live-identity comparison once.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub(crate) opened_changed_nanos: u64,
    /// The file birth (unix nanos) of that open: the object generation the
    /// stored ctime belongs to. Zero (unavailable) never adopts the ctime.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub(crate) opened_birth_nanos: u64,
    /// Local-only exact current-context acceptance. Appended for old readers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) upload_context_receipt: Option<upload_context_receipt::Receipt>,
}
// Verify the EXISTING native entry-layout contract during compile-only checks.
// No budget, whitelist or substitute bound is changed.
#[cfg(all(test, target_os = "macos", target_pointer_width = "64"))]
const _: () = assert!(std::mem::size_of::<ScanIndexEntry>() == 560);

impl ScanIndexEntry {
    /// The listing stamp: the same size (or a certified Codex EOF fragment
    /// of it), the same mtime nanos and, when both are known, the same file
    /// birth. ctime, mode, xattrs and links never count (the re-read rule:
    /// content, never ctime). It only decides "unchanged"; acquisition still
    /// picks the read mode.
    pub(in crate::snapshots) fn same_listing_stamp(
        &self,
        len: u64,
        modified_nanos: Option<u64>,
        birth_nanos: Option<u64>,
        fragment: Option<codex_fragment::Stamp>,
    ) -> bool {
        self.same_stamp_with_mtime(
            self.modified_unix_nanos,
            len,
            modified_nanos,
            birth_nanos,
            fragment,
        )
    }

    pub(in crate::snapshots) fn same_stamp_with_mtime(
        &self,
        stored_modified_nanos: Option<u64>,
        len: u64,
        modified_nanos: Option<u64>,
        birth_nanos: Option<u64>,
        fragment: Option<codex_fragment::Stamp>,
    ) -> bool {
        (self.size_bytes == len
            || self
                .codex_fragment
                .as_ref()
                .is_some_and(|bound| bound.matches(self.size_bytes, len, fragment)))
            && modified_nanos.is_some()
            && stored_modified_nanos == modified_nanos
            && (self.opened_birth_nanos == 0 || birth_nanos == Some(self.opened_birth_nanos))
    }

    pub(in crate::snapshots) fn same_listing_stamp_as(&self, metadata: &fs::Metadata) -> bool {
        let modified = metadata.modified().ok().and_then(unix_nanos);
        // An entry stored without mtime nanos compares at whole seconds.
        let stored = self.modified_unix_nanos.or_else(|| {
            modified.filter(|nanos| nanos / 1_000_000_000 == self.modified_unix_seconds)
        });
        self.same_stamp_with_mtime(
            stored,
            metadata.len(),
            modified,
            metadata.created().ok().and_then(unix_nanos),
            codex_fragment::Stamp::metadata(metadata),
        )
    }

    pub(in crate::snapshots) fn codex_recovery_is_pending(&self) -> bool {
        self.codex_captured_joined_member_set.is_some()
            || self.codex_captured_tier_receipt_required
            || self.codex_captured_tier_receipt.is_some()
            || self.codex_captured_uncommitted
    }
    pub(in crate::snapshots) fn codex_history_is_protected(&self) -> bool {
        self.codex_protected_owner.is_some()
            || self.codex_joined_member_set.is_some()
            || self.codex_captured_joined_member_set.is_some()
            || self.codex_applied_tier_receipt.is_some()
            || self.codex_applied_tier_receipt_required
            || self.codex_captured_tier_receipt.is_some()
            || self.codex_captured_tier_receipt_required
            || self.codex_captured_uncommitted
    }
}
crate::heap_layout_bound::fields!(ScanIndexEntry; codex_fragment, size_bytes, modified_unix_seconds, modified_unix_nanos, source_file_fingerprint, last_snapshot_fingerprint, last_upload_body_witness, effective_upload_body_witness_revision, scan_identity_version, codex_joined_member_set, codex_captured_joined_member_set, codex_protected_owner, codex_applied_tier_receipt, codex_applied_tier_receipt_required, codex_captured_tier_receipt, codex_captured_tier_receipt_required, codex_captured_uncommitted, codex_counting_v2, codex_counting_owner, opened_changed_nanos, opened_birth_nanos, upload_context_receipt);
