//! Discovery: finding transcript candidates and opening them.
//!
//! `candidate_open` resolves configured roots, opens one candidate and
//! records its opened-object identity, and holds the per-page budgets for
//! history files adopted only for a new body witness. `traversal` holds the
//! bounded walk's persisted state.

pub(super) mod candidate_open;
pub(super) mod traversal;
