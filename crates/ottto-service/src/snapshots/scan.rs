//! Scan-time readers and limits shared by the source scanners: JSON field
//! readers, the source session id a transcript resolves to, and the epoch
//! gates and listing/retry limits.

pub(super) mod accumulator;
#[cfg(unix)]
pub(crate) mod durable_sources;
pub(super) mod entry;
pub(super) mod identity;
pub(super) mod json_fields;
pub(super) mod launch_demand;
pub(super) mod limits;
pub(super) mod lines;
pub(super) mod owned_scan;
pub(crate) mod ownership_diagnostics;
pub(crate) mod read_cause;
pub(super) mod source_session_id;
