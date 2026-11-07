//! Discovery: finding transcript candidates and opening them.
//!
//! `traversal` holds the bounded walk over the configured roots, and its
//! `state` child what the walk persists between pages. `directory` reads the
//! walk's directories under a per-tick budget and reconciles indexed keys the
//! walk did not find. `candidate` holds the candidate file, its page census and
//! the decision and selection diagnostics, and admits one traversal path as a
//! candidate. `candidate_open` resolves configured roots, opens one candidate
//! and records its opened-object identity, and holds the per-page budgets for
//! history files adopted only for a new body witness. `retention` holds the
//! owed-key exemption from the discovery window that every age gate applies.

pub(super) mod candidate;
pub(super) mod candidate_open;
pub(super) mod directory;
pub(super) mod retention;
pub(super) mod traversal;
