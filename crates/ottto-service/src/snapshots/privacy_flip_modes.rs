//! The delivery-context inputs a privacy flip moves, shared by the flip tests.
//! Synthetic inputs.
use super::SnapshotUploadPolicy;
use serde_json::{json, Value};

/// Every input of the delivery context: the five settings, the attribution
/// key, the cache capability and the copy-unproven capability.
#[derive(Clone, Copy)]
pub(crate) struct Mode {
    pub(crate) policy: SnapshotUploadPolicy,
    pub(crate) key: u8,
    pub(crate) cache: bool,
    pub(crate) copy: bool,
}
pub(crate) type Flip = (&'static str, fn(&mut Mode));
pub(crate) const FLIPS: [Flip; 8] = [
    ("titles", |m| flip(&mut m.policy.session_titles_enabled)),
    ("workspace", |m| {
        flip(&mut m.policy.workspace_labels_enabled)
    }),
    ("links", |m| flip(&mut m.policy.session_artifacts_enabled)),
    ("attribution", |m| {
        flip(&mut m.policy.session_attribution_enabled)
    }),
    ("labels", |m| {
        flip(&mut m.policy.session_attribution_labels_enabled)
    }),
    ("key", |m| m.key ^= 1),
    ("cache", |m| flip(&mut m.cache)),
    ("copy", |m| flip(&mut m.copy)),
];
fn flip(value: &mut bool) {
    *value = !*value;
}

pub(crate) fn all(value: bool) -> SnapshotUploadPolicy {
    SnapshotUploadPolicy {
        session_titles_enabled: value,
        workspace_labels_enabled: value,
        session_artifacts_enabled: value,
        session_attribution_enabled: value,
        session_attribution_labels_enabled: value,
    }
}

/// A Claude user line whose tool result opens pull request `n`.
pub(crate) fn link(session: &str, timestamp: &str, n: u32) -> Value {
    json!({"timestamp":timestamp,"sessionId":session,"message":{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":format!("Opened https://github.com/ottto-ai/repo/pull/{n}")}]}]}})
}
