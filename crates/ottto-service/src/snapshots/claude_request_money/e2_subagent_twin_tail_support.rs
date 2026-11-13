//! Test support: the decision before subagent twins counted a shared tail
//! once. A later home whose copied skips an earlier home all holds kept
//! them, and a held response inside the copy slack before its birth counted
//! in both homes (n+1).

use super::*;

/// That earlier body: the page keeps every native skip and runs no twin
/// pass, so the slack tail counts in both homes.
pub(crate) fn pre_fix_twin_tail(items: &mut [SnapshotItem]) {
    for item in items {
        if let Some(fold) = item.claude_money.as_deref_mut() {
            fold.twin_pending = false;
        }
    }
}
