//! The folder login ledger's persisted shape (state layout 5). Only the stored
//! format lives here; the code that fills and reads it ships separately.

use serde::{Deserialize, Serialize};

/// One folder's durable evidence: hashes, flags and file digests, no email.
/// Absent members default to "not qualified".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct FolderRecord {
    fresh: bool,
    /// Sticky once set.
    mixed: bool,
    login: Option<String>,
    org: Option<String>,
    owner_proven: bool,
    census_complete: bool,
    /// Unix seconds, floored to the hour.
    covered_from: Option<i64>,
    /// Sorted 8-byte location digests.
    matched: Vec<u64>,
    reoffer: u8,
    reoffer_remaining: u64,
    reoffer_moved_at: i64,
    /// Sorted 8-byte location digests.
    reoffer_owed: Vec<u64>,
    reoffer_revision: u64,
}
crate::heap_layout_bound::fields!(FolderRecord; fresh, mixed, login, org, owner_proven, census_complete, covered_from, matched, reoffer, reoffer_remaining, reoffer_moved_at, reoffer_owed, reoffer_revision);

// Admission classes: flags, counts and times are N; `login`/`org` are identity
// hashes (H); `matched`/`reoffer_owed` hold location digests truncated to u64,
// so they are N-typed, not H's fixed 32 bytes. Not part of any retained body.
crate::durable_tail_codec::durable_struct!(FolderRecord {
    N fresh: bool,
    N mixed: bool,
    H login: Option<String>,
    H org: Option<String>,
    N owner_proven: bool,
    N census_complete: bool,
    N covered_from: Option<i64>,
    N matched: Vec<u64>,
    N reoffer: u8,
    N reoffer_remaining: u64,
    N reoffer_moved_at: i64,
    N reoffer_owed: Vec<u64>,
    N reoffer_revision: u64,
});
