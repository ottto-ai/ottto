//! E3: withheld-account hold accounting.
use crate::local_resource_diagnostics::{withheld_event, WithheldEvent};

/// A hold released because its file was proved absent: counted.
pub(super) fn released_deleted() {
    withheld_event(WithheldEvent::ReleasedDeleted, 1);
}
