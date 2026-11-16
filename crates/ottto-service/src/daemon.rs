//! Internal daemon state and local-control projections.
//! Keeps the root API stable while grouping state, health and repair ownership.
//! Called by the crate facade and the source-health projection.

pub(super) mod health;
pub(super) mod repair;
pub(super) mod state;
pub(super) mod status;
pub(super) mod verification;
