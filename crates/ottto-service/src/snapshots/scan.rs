//! Scan-time readers and limits shared by the source scanners: JSON field
//! readers, the source session id a transcript resolves to, and the epoch
//! gates and listing/retry limits.

pub(super) mod accumulator;
pub(super) mod entry;
pub(super) mod json_fields;
pub(super) mod launch_demand;
pub(super) mod limits;
pub(super) mod lines;
pub(super) mod scan_identity;
pub(super) mod source_session_id;
