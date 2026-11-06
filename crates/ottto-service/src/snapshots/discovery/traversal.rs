//! Discovery traversal: the bounded walk over the configured scan roots.
//!
//! `state` holds what the walk persists between pages: its checkpoint, queued
//! paths, counts and residue, with the records kept beside them.

pub(in crate::snapshots) mod state;
