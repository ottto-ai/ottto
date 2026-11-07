//! Discovery retention: the owed-key exemption from the discovery window
//! shared by every age gate, the account-move observations it is derived
//! beside, the frozen-window check on an opened candidate, and the effective
//! backfill window.

use crate::snapshots::*;

/// Per-caller derived view, bounded by the held inventory; never move proof.
pub(in crate::snapshots) struct AccountMoveObservations {
    pub(in crate::snapshots) paths: BTreeMap<String, Vec<String>>,
    pub(in crate::snapshots) through: Option<String>,
}

/// Owed-key discovery retention, the one shared exemption from the discovery
/// window (`docs/diagnostics.md`, "Owed-key discovery retention"). Contract: a
/// key owed by any registered source stays discoverable and observed whatever
/// its age while owed, so reconciliation never prunes it; its growth takes the
/// counted Tail path; only a validated catch-up or a proven, counted removal
/// releases it; it is never a Full cause. File-size caps still apply.
/// Grown since committed: retention ends when the growth is committed
/// (`size_bytes` catches up). Equal and truncated lengths gain no exemption.
/// Source-agnostic (the Claude walk, candidate and open gates, the Codex roster).
/// Register a source with its field, its
/// line in `discovery_retention!` and `unverified`, and its line in `owes`.
#[derive(Clone, Copy)]
pub(in crate::snapshots) struct DiscoveryRetention<'a> {
    /// Entries; an unverified sampled generation (`sampled_audit`) is owed.
    pub(in crate::snapshots) files: &'a SharedMap<String, ScanIndexEntry>,
    /// Correctness hold: unresolved ownership debt stays discoverable, including growth.
    /// Only the approved interim withheld_reparse{start,evidence,growth} exception may Full.
    /// At the hold cap no new exemption is invented; unknown identity cannot memo-Skip.
    pub(in crate::snapshots) account_holds: &'a BTreeMap<String, String>,
    pub(in crate::snapshots) memo: Option<&'a withheld_account::Memo>,
    /// Bounded page diagnostics only; never a retention/selection input.
    pub(in crate::snapshots) growth: Option<&'a discovery_growth::Page>,
}

impl<'a> DiscoveryRetention<'a> {
    pub(in crate::snapshots) fn observe_stamped_growth(
        &self,
        path: &Path,
        len: u64,
        modified: u64,
        stamp: Option<codex_fragment::Stamp>,
    ) {
        let key = local_index_key(path);
        if self.account_holds.contains_key(&key) {
            // This gate already has physical presence; invalidate an earlier
            // absence even if the file disappears again before page completion.
            if let Some(memo) = self.memo {
                memo.reset_absence(&key);
            }
        }
        if let Some(page) = self.growth {
            if self
                .files
                .get(&key)
                .is_some_and(|entry| codex_fragment::grown(entry, len, stamp))
            {
                page.observe_stamped(key, len, modified, stamp);
            }
        }
    }

    /// Owed by a registered source: the discovery window does not apply.
    pub(in crate::snapshots) fn owes(&self, path: &Path) -> bool {
        sampled_audit::path_requires_verification(self.files, path)
            || self.account_holds.contains_key(&local_index_key(path))
    }

    pub(in crate::snapshots) fn owes_stamped(
        &self,
        source: SnapshotSource,
        path: &Path,
        current_len: u64,
        stamp: Option<codex_fragment::Stamp>,
    ) -> bool {
        let grown = self
            .files
            .get(&local_index_key(path))
            .is_some_and(|entry| codex_fragment::grown(entry, current_len, stamp));
        if grown {
            crate::local_resource_diagnostics::discovery_retained_grown(source.api_slug());
        }
        grown || self.owes(path)
    }
}

#[cfg(test)]
mod discovery_support {
    use super::*;
    impl<'a> DiscoveryRetention<'a> {
        /// Use the current metadata already held by the gate, never another stat.
        /// Count an aged growth-retention decision once, even if another arm owes it.
        pub(in crate::snapshots) fn owes_with_len(
            &self,
            source: SnapshotSource,
            path: &Path,
            current_len: u64,
        ) -> bool {
            self.owes_stamped(source, path, current_len, None)
        }
        /// Entries only: no other owed source (tests and index-free callers).
        pub(in crate::snapshots) fn unverified(
            files: &'a SharedMap<String, ScanIndexEntry>,
        ) -> Self {
            static NONE: BTreeMap<String, String> = BTreeMap::new();
            Self {
                files,
                account_holds: &NONE,
                memo: None,
                growth: None,
            }
        }
    }
}

pub(in crate::snapshots) fn opened_candidate_is_within_frozen_window(
    candidate: &CandidateFile,
    census_unix_seconds: Option<u64>,
    backfill_window_days: u64,
) -> bool {
    census_unix_seconds.map_or(true, |now| {
        is_recent_enough_at(candidate.modified_unix_seconds, now, backfill_window_days)
    })
}

pub(in crate::snapshots) fn effective_backfill_window_days(
    requested_backfill_window_days: u64,
) -> u64 {
    requested_backfill_window_days.min(BACKFILL_WINDOW_DAYS)
}
