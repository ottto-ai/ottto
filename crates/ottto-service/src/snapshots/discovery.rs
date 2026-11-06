//! Discovery: finding transcript candidates and opening them.
//!
//! `candidate` holds the candidate file, its page census and the decision
//! and selection diagnostics, and admits one traversal path as a candidate.
//! `candidate_open` resolves configured roots, opens one candidate and
//! records its opened-object identity, and holds the per-page budgets for
//! history files adopted only for a new body witness. `traversal` holds the
//! bounded walk's persisted state.

pub(super) mod candidate;
pub(super) mod candidate_open;
pub(super) mod traversal;
