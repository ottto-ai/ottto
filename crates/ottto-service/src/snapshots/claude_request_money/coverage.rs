//! What the census proves about a page's families, for the P1 money shadow.
//!
//! A family row is complete only when the census covers its family and P1
//! has no reason of its own. The census side is this seam: one view per
//! page, asked once per family. Until StateMissing's Fix 3 exists the
//! interim view never says `Covered` (nothing local proves a family
//! disjoint) and never says `Missing` (`current_for` cannot tell absent
//! evidence from unverified evidence), and the holder view is incomplete
//! for both kinds, so every unit with no telemetry claimant is held.
//!
//! The Fix 3 adapter replaces `InterimFamilyCoverage` in one constructor
//! (`snapshot_sync.rs`): `Covered` only from the strong `settled_for(root)`,
//! every other case from a typed key status, and the holder view from the
//! decision view's strong comparison (never fence coverage). `Covered` is
//! negative-safety evidence only: no ownership and no owned start.

use serde::Serialize;
use std::collections::BTreeMap;

/// Why the census does not cover a family (the first that applies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CensusReason {
    /// The duplicate fence is structurally invalid.
    FenceInvalid,
    /// The page's census is not complete.
    CensusIncomplete,
    /// Usage-authority retry families remain.
    AuthorityRetry,
    /// No strong decision view exists (before Fix 3).
    StrongViewUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Covered/Missing belong to the future strong-view adapter.
pub(crate) enum FamilyCensus {
    Covered,
    Unknown(CensusReason),
    /// Census keys with no usable record (`more` past the listed ones).
    Missing {
        keys: Vec<String>,
        more: u32,
    },
}

impl FamilyCensus {
    /// The family row's `census`, `census_reason` and `key_statuses`. Keys
    /// are paths: only their count is written.
    pub(crate) fn wire(
        &self,
    ) -> (
        &'static str,
        Option<CensusReason>,
        BTreeMap<&'static str, u64>,
    ) {
        match self {
            Self::Covered => ("covered", None, BTreeMap::new()),
            Self::Unknown(reason) => ("unknown", Some(*reason), BTreeMap::new()),
            Self::Missing { keys, more } => (
                "missing",
                None,
                BTreeMap::from([("missing", keys.len() as u64 + u64::from(*more))]),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HolderKind {
    Request,
    Message,
}

pub(crate) trait FamilyCoverage {
    fn family(&self, root: &str) -> FamilyCensus;
    fn holder_view_complete(&self, kind: HolderKind) -> bool;
}

/// The page's holder view, read once from the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaudeHolderView {
    pub(crate) request: bool,
    pub(crate) message: bool,
}

impl ClaudeHolderView {
    pub(crate) fn of(coverage: &dyn FamilyCoverage) -> Self {
        Self {
            request: coverage.holder_view_complete(HolderKind::Request),
            message: coverage.holder_view_complete(HolderKind::Message),
        }
    }

    pub(crate) fn complete(&self) -> bool {
        self.request && self.message
    }
}

/// The census seam until Fix 3: never `Covered`, never `Missing`, and the
/// holder view is incomplete.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct InterimFamilyCoverage {
    pub(crate) fence_invalid: bool,
    pub(crate) census_complete: bool,
    pub(crate) authority_retry: bool,
}

impl FamilyCoverage for InterimFamilyCoverage {
    fn family(&self, _root: &str) -> FamilyCensus {
        FamilyCensus::Unknown(if self.fence_invalid {
            CensusReason::FenceInvalid
        } else if !self.census_complete {
            CensusReason::CensusIncomplete
        } else if self.authority_retry {
            CensusReason::AuthorityRetry
        } else {
            CensusReason::StrongViewUnavailable
        })
    }

    fn holder_view_complete(&self, _kind: HolderKind) -> bool {
        false
    }
}

/// A census that covers every family and a complete holder view: what the
/// Fix 3 adapter will say for a settled machine (tests only).
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CoveredForTest;

#[cfg(test)]
impl FamilyCoverage for CoveredForTest {
    fn family(&self, _root: &str) -> FamilyCensus {
        FamilyCensus::Covered
    }

    fn holder_view_complete(&self, _kind: HolderKind) -> bool {
        true
    }
}
