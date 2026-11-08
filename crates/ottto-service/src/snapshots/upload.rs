//! Upload-side scan-index state: which entities a save after an upload may
//! commit, and the re-offer, quarantine and body-witness stamp state that
//! decides what the next pass offers again.

mod committable_subset;
pub(super) mod finalize;
mod reoffer_quarantine;
#[cfg(test)]
pub(in crate::snapshots) mod tests;
