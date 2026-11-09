//! Upload-side scan-index state: which entities a save after an upload may
//! commit, and the re-offer, quarantine and body-witness stamp state that
//! decides what the next pass offers again.

mod committable_subset;
pub(crate) mod context_read;
pub(super) mod finalize;
pub(crate) mod freshness_debt;
pub(crate) mod money_freshness;
mod reoffer_quarantine;
pub(crate) mod terminal_contract_retry;
#[cfg(test)]
pub(in crate::snapshots) mod tests;
