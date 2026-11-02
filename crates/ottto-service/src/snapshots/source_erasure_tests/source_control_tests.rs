//! Web disable and install delivered on the health heartbeat reach PR-A's
//! marker and eraser, in revision order, one source at a time.
use super::*;
use crate::snapshot_sync::source_control::{apply, response_for_test, transport_source};

const CODEX: SnapshotSource = SnapshotSource::Codex;
const CLAUDE: SnapshotSource = SnapshotSource::ClaudeCode;

fn heard(f: &Fixture, source: SnapshotSource, revision: u64, state: &str) -> bool {
    let response = response_for_test("device", source.api_slug(), revision, state);
    apply(&f.support, "device", &response)
}

fn marker(f: &Fixture, source: SnapshotSource) -> Option<String> {
    source_marker(&f.support, source)
}

/// [behaviour] Revision order wins over arrival order; a duplicate does no
/// work; a failed local disable stays off until a newer explicit install.
#[test]
fn heartbeat_control_applies_in_revision_order_and_erases_only_that_source() {
    let f = Fixture::new();
    let codex = f.canaries(CODEX);
    let claude = f.canaries(CLAUDE);

    assert!(heard(&f, CODEX, 1, "disabled"));
    assert_eq!(marker(&f, CODEX).as_deref(), Some("pending"));
    assert_eq!(
        enabled_snapshot_sources_in(&device(), &f.support),
        vec![CLAUDE]
    );
    assert_kept(&codex);
    assert_eq!(f.erase(CODEX), 0);
    assert_gone(&codex);
    assert_kept(&claude);
    assert!(!heard(&f, CODEX, 1, "disabled"), "duplicate: no new work");
    assert_eq!(marker(&f, CODEX).as_deref(), Some("done"));

    assert!(
        heard(&f, CODEX, 2, "enabled"),
        "explicit install reconnects"
    );
    assert_eq!(f.erase(CODEX), 0);
    assert_eq!(marker(&f, CODEX), None);
    assert!(!heard(&f, CODEX, 1, "disabled"), "a delayed older disable");
    assert_eq!(marker(&f, CODEX), None);

    // A late local install completion cannot outlive a newer disable.
    assert!(heard(&f, CODEX, 3, "disabled"));
    reconnect_snapshot_source(&f.support, CODEX).unwrap();
    assert!(heard(&f, CODEX, 3, "disabled"), "the same revision holds");
    assert_eq!(marker(&f, CODEX).as_deref(), Some("pending"));

    // A local disable whose POST failed: the older enable cannot clear it.
    assert!(heard(&f, CODEX, 4, "enabled"));
    assert_eq!(f.erase(CODEX), 0);
    disable_snapshot_source(&f.support, CODEX).unwrap();
    assert!(!heard(&f, CODEX, 4, "enabled"));
    assert_eq!(marker(&f, CODEX).as_deref(), Some("pending"));

    // Another device's control, or none at all, is a no-op.
    let other = response_for_test("other-device", "claude_code", 9, "disabled");
    assert!(!apply(&f.support, "device", &other));
    assert!(!apply(&f.support, "device", &json!({"accepted": true})));
    assert_eq!(marker(&f, CLAUDE), None);
    assert_kept(&claude);
}

/// [behaviour] One source's failed marker write keeps only that source owed.
#[test]
fn failed_marker_write_isolates_to_its_source() {
    let f = Fixture::new();
    let codex_marker = f.support.join("snapshots/codex.source-disabled");
    fs::create_dir_all(codex_marker.join("blocks-the-rename")).unwrap();
    let mut response = response_for_test("device", "codex", 5, "enabled");
    let claude = response_for_test("device", "claude_code", 6, "disabled");
    response["source_control"]["sources"]
        .as_array_mut()
        .unwrap()
        .push(claude["source_control"]["sources"][0].clone());

    assert!(apply(&f.support, "device", &response));
    assert_eq!(marker(&f, CLAUDE).as_deref(), Some("pending"));
    let applied = crate::backfill::load_backfill_state(&f.support).source_control_revisions;
    assert_eq!(applied.get("claude_code"), Some(&("device".into(), 6)));
    assert_eq!(applied.get("codex"), None, "codex stays owed");
}

/// [behaviour] A Mac with every source disabled still authenticates health,
/// so it hears the install that brings a source back.
#[test]
fn all_disabled_mac_still_polls_through_a_granted_source() {
    let f = Fixture::new();
    disable_snapshot_source(&f.support, CODEX).unwrap();
    disable_snapshot_source(&f.support, CLAUDE).unwrap();
    assert!(enabled_snapshot_sources_in(&device(), &f.support).is_empty());
    assert_eq!(transport_source(&device()), Some(CODEX));
    let ungranted = LocalDeviceBinding {
        sources: Vec::new(),
        ..device()
    };
    assert_eq!(transport_source(&ungranted), None);

    assert!(heard(&f, CLAUDE, 1, "enabled"));
    assert_eq!(f.erase(CLAUDE), 0);
    assert_eq!(
        enabled_snapshot_sources_in(&device(), &f.support),
        vec![CLAUDE]
    );
}
